package queue

import (
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Bounded claiming for the file backend.
//
// Without it, Processor.processQueue falls through to ListMessages on every
// tick, and List opens, JSON-decodes and tombstone-checks *every* message in
// the queue. That cost is O(queue depth) and it is paid before a single worker
// is dispatched, so raising the worker count barely moves throughput: measured
// draining a 20,000-message backlog, 5 workers gave 21.0/s and 20 gave 23.4/s.
// Worse, it means the server slows down precisely when it is furthest behind,
// which is the wrong shape for a queue.
//
// Claiming reads directory entries — names only, no file I/O per message —
// takes the first `limit` that nobody is working on, and decodes just those.
// The same trade `Count` already makes for the same reason.
//
// The lease is in-process, which is honest for this backend: a directory of
// files has no way to make "claim these N rows" atomic across processes the way
// Postgres does with SKIP LOCKED. That is not a regression, because before this
// there was no claim at all — the processor guarded against double-processing
// with an in-memory map either way. A restart drops every lease, which is
// correct: nothing is being worked on after a restart.

type fileClaim struct {
	workerID string
	until    time.Time
}

var (
	fileClaimMu sync.Mutex
	fileClaims  = map[string]fileClaim{}
)

// claimable reports whether nobody currently holds an unexpired lease on id.
// Caller holds fileClaimMu.
func claimable(id string, now time.Time) bool {
	claim, held := fileClaims[id]
	return !held || now.After(claim.until)
}

// ClaimMessages takes up to limit messages that no worker is currently
// processing, leasing them to workerID until leaseUntil.
//
// Ordering is by message ID, which is timestamp-prefixed, so this approximates
// first-in-first-out. It deliberately does not reproduce ListMessages' sort by
// priority: that sort requires decoding every message in the queue, which is
// the cost this exists to avoid. Priority ordering across a large backlog is
// worth less than draining the backlog at all.
func (fs *FileStorageBackend) ClaimMessages(queueType QueueType, limit int, workerID string, leaseUntil time.Time) ([]Message, error) {
	if limit <= 0 {
		return []Message{}, nil
	}
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("worker id is required")
	}
	if err := validateQueueType(queueType); err != nil {
		return nil, err
	}

	root, err := openRoot(fs.queueDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return []Message{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()

	dir, err := openChildDir(root, string(queueType), false)
	if errors.Is(err, os.ErrNotExist) {
		return []Message{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if validateMessageID(id) != nil {
			// List reports a corrupt filename as an error and refuses the whole
			// queue. Claiming skips it instead: one bad name must not stop every
			// other message in the queue from being delivered.
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)

	now := time.Now()
	claimed := make([]string, 0, limit)
	fileClaimMu.Lock()
	for _, id := range ids {
		if len(claimed) >= limit {
			break
		}
		if !claimable(id, now) {
			continue
		}
		fileClaims[id] = fileClaim{workerID: workerID, until: leaseUntil}
		claimed = append(claimed, id)
	}
	fileClaimMu.Unlock()

	messages := make([]Message, 0, len(claimed))
	for _, id := range claimed {
		data, err := readFileAt(dir, id+".json")
		if err != nil {
			// Gone between the listing and the read: delivered by someone else,
			// or consumed. Not this worker's problem, and not an error.
			fs.ReleaseMessageClaim(id, workerID)
			continue
		}
		msg, err := decodeMessage(data, id, queueType)
		if err != nil {
			fs.ReleaseMessageClaim(id, workerID)
			continue
		}
		// A message whose enqueue was already consumed is not deliverable; List
		// filters these and so must this, or a consumed message is delivered
		// twice.
		if err := fs.suppressConsumed(msg); err != nil {
			fs.ReleaseMessageClaim(id, workerID)
			continue
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// ReleaseMessageClaim drops the lease so the message can be picked up again.
//
// An empty workerID releases regardless of holder, matching the Postgres
// backend, which the processor relies on when cleaning up.
func (fs *FileStorageBackend) ReleaseMessageClaim(id, workerID string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("message id is required")
	}
	fileClaimMu.Lock()
	defer fileClaimMu.Unlock()
	claim, held := fileClaims[id]
	if !held {
		return nil
	}
	if strings.TrimSpace(workerID) != "" && claim.workerID != workerID {
		return nil
	}
	delete(fileClaims, id)
	return nil
}

// forgetExpiredFileClaims drops leases whose deadline has passed.
//
// Without this the map grows for every message that is claimed and never
// released — a crash mid-delivery, or a message that leaves the queue by
// another path. That is the same unbounded-growth shape as the tombstone leak,
// on a smaller scale.
func forgetExpiredFileClaims(now time.Time) int {
	fileClaimMu.Lock()
	defer fileClaimMu.Unlock()
	removed := 0
	for id, claim := range fileClaims {
		if now.After(claim.until) {
			delete(fileClaims, id)
			removed++
		}
	}
	return removed
}
