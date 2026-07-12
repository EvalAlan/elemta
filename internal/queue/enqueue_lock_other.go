//go:build !linux

package queue

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	enqueueLockStaleAfter = 5 * time.Minute
	enqueueLockPoll       = 10 * time.Millisecond
)

type enqueueLockOwner struct {
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at_unix_nano"`
}

func newEnqueueLockToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// acquireEnqueueLock uses an atomic claim directory on platforms without
// flock. A token-specific owner file makes release safe even if a stale claim
// is concurrently quarantined and replaced. The heartbeat prevents a live,
// long-running holder from being considered stale after staleAfter.
func acquireEnqueueLock(path string) (func(), error) {
	token, err := newEnqueueLockToken()
	if err != nil {
		return nil, fmt.Errorf("create lock token: %w", err)
	}
	ownerName := "owner-" + token + ".json"
	owner := enqueueLockOwner{Token: token, CreatedAt: time.Now().UnixNano()}
	payload, err := json.Marshal(owner)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(enqueueLockStaleAfter + time.Minute)
	for {
		// Prepare ownership before publishing the directory, so a crash can
		// never leave an ownerless claim that cannot be safely recovered.
		prepared := path + ".claim-" + token
		if err := os.Mkdir(prepared, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		preparedOwner := filepath.Join(prepared, ownerName)
		if err := os.WriteFile(preparedOwner, payload, 0600); err != nil {
			_ = os.RemoveAll(prepared)
			return nil, fmt.Errorf("write lock ownership: %w", err)
		}
		if err := os.Rename(prepared, path); err == nil {
			ownerPath := filepath.Join(path, ownerName)
			if _, err := os.Stat(ownerPath); err != nil {
				_ = os.RemoveAll(path)
				return nil, fmt.Errorf("write lock ownership: %w", err)
			}
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				ticker := time.NewTicker(enqueueLockStaleAfter / 3)
				defer ticker.Stop()
				defer close(done)
				for {
					select {
					case now := <-ticker.C:
						// Updating both timestamps makes stale detection robust on
						// filesystems whose directory mtime semantics differ.
						_ = os.Chtimes(ownerPath, now, now)
						_ = os.Chtimes(path, now, now)
					case <-stop:
						return
					}
				}
			}()
			return func() {
				close(stop)
				<-done
				// This name includes our unguessable token. If path now names a
				// later generation, this cannot remove its owner file.
				_ = os.Remove(filepath.Join(path, ownerName))
				_ = os.Remove(path)
			}, nil
		} else if !errors.Is(err, os.ErrExist) {
			_ = os.RemoveAll(prepared)
			return nil, err
		}
		_ = os.RemoveAll(prepared)

		info, statErr := os.Stat(path)
		if statErr == nil && time.Since(info.ModTime()) > enqueueLockStaleAfter {
			entries, readErr := os.ReadDir(path)
			if readErr == nil && len(entries) == 1 {
				observed := entries[0].Name()
				var recorded enqueueLockOwner
				raw, readOwnerErr := os.ReadFile(filepath.Join(path, observed))
				if readOwnerErr == nil && json.Unmarshal(raw, &recorded) == nil &&
					observed == "owner-"+recorded.Token+".json" &&
					recorded.CreatedAt > 0 && time.Since(time.Unix(0, recorded.CreatedAt)) > enqueueLockStaleAfter {
					quarantine := path + ".stale-" + token
					if os.Rename(path, quarantine) == nil {
						// Verify the quarantined directory is the exact generation
						// observed before rename. Never delete a replacement owner.
						qraw, qerr := os.ReadFile(filepath.Join(quarantine, observed))
						var qowner enqueueLockOwner
						if qerr == nil && json.Unmarshal(qraw, &qowner) == nil && qowner.Token == recorded.Token {
							_ = os.RemoveAll(quarantine)
							continue
						}
						if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
							_ = os.Rename(quarantine, path)
						}
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out acquiring enqueue lock")
		}
		time.Sleep(enqueueLockPoll)
	}
}
