//go:build linux

package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// acquireEnqueueLock is an advisory lock: the kernel releases it on process
// death, unlike a sentinel directory, so interrupted enqueue is retryable.
//
// flock protects an inode, not a path, so a lock file that is removed while
// someone waits on it would split waiters into two independently locked
// generations. Lock files used to be kept forever for that reason, one per
// message ever enqueued, so the directory grew without bound. Now a lock
// counts only if, once held, the path still names the inode that was
// locked; if the file was pruned in the meantime this starts again on the
// current one. That makes removing an unheld lock file safe
// (pruneEnqueueLocks).
func acquireEnqueueLock(path string) (func(), error) {
	for {
		fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return nil, err
		}
		if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		current, err := lockIsCurrent(fd, path)
		if err != nil {
			_ = unix.Flock(fd, unix.LOCK_UN)
			_ = unix.Close(fd)
			return nil, err
		}
		if current {
			return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
		}
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}
}

// lockIsCurrent reports whether path still names the inode open as fd.
func lockIsCurrent(fd int, path string) (bool, error) {
	var held, now unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return false, err
	}
	if err := unix.Lstat(path, &now); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return held.Dev == now.Dev && held.Ino == now.Ino, nil
}

// enqueueLockIdleAge is how long a lock file must have been left alone
// before pruning considers it. An enqueue holds its lock for milliseconds,
// so this only keeps pruning away from files in active use; correctness
// comes from the lock itself.
const enqueueLockIdleAge = time.Hour

// pruneEnqueueLocks removes enqueue lock files in dir that are older than
// cutoff and that nobody holds. Each is locked without waiting before it is
// removed, and removed only while still current, so a holder is never
// disturbed and a waiter on the removed inode starts again on a new one.
func pruneEnqueueLocks(dir string, cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ".enqueue-") || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(dir, name)
		ok, err := removeIdleLock(path)
		if err != nil {
			return removed, fmt.Errorf("prune enqueue lock %q: %w", name, err)
		}
		if ok {
			removed++
		}
	}
	return removed, nil
}

// removeIdleLock removes the lock file at path if it can be locked at once.
func removeIdleLock(path string) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil // in use
		}
		return false, err
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	current, err := lockIsCurrent(fd, path)
	if err != nil || !current {
		return false, err
	}
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	return true, nil
}
