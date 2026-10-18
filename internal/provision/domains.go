package provision

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/EvalAlan/elemta/internal/config"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

type FileDomains struct{ Path string }

func (f FileDomains) Lock(ctx context.Context) (func(), error) {
	// The shared runtime config also supplies the lock shared by local CLI and
	// dashboard processes. Use a stable sidecar, because config writes rename it.
	// #nosec G304 -- Path is the operator's startup configuration path
	file, err := os.OpenFile(f.Path+".provision.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func (f FileDomains) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// #nosec G304 -- operator's configuration path, never request-derived
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		LocalDomains []string `toml:"local_domains"`
	}
	if err = toml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	sort.Strings(doc.LocalDomains)
	return doc.LocalDomains, nil
}
func (f FileDomains) Set(ctx context.Context, names []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// #nosec G304 -- operator's configuration path, never request-derived
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	data, err = config.SetTOMLValue(data, "", "local_domains", names)
	if err != nil {
		return err
	}
	var parsed map[string]any
	if err = toml.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("invalid updated config: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".mail-domains-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

// Notify invalidates SMTP recipient existence caches across the processes that
// share this runtime configuration, including both positive and negative hits.
func (f FileDomains) Notify() error {
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".directory-version-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = fmt.Fprintln(tmp, time.Now().UnixNano()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path+".provision-generation")
}
