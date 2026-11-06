//go:build linux

package queue

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Regression: unlinking a flock file after unlock lets a third client lock a
// new inode while a waiter still owns the old one.
func TestEnqueueLockKeepsOneInodeAcrossWaiters(t *testing.T) {
	path := t.TempDir() + "/lock"
	first, err := acquireEnqueueLock(path)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan int, 2)
	release := make(chan struct{})
	var active int32
	for i := 0; i < 2; i++ {
		go func(i int) {
			unlock, err := acquireEnqueueLock(path)
			if err != nil {
				entered <- -1
				return
			}
			if atomic.AddInt32(&active, 1) != 1 {
				entered <- -2
			} else {
				entered <- i
			}
			<-release
			atomic.AddInt32(&active, -1)
			unlock()
		}(i)
	}
	time.Sleep(20 * time.Millisecond)
	first()
	if got := <-entered; got < 0 {
		t.Fatalf("split lock generation: %d", got)
	}
	select {
	case got := <-entered:
		t.Fatalf("second waiter entered concurrently: %d", got)
	case <-time.After(30 * time.Millisecond):
	}
	release <- struct{}{}
	if got := <-entered; got < 0 {
		t.Fatalf("split lock generation: %d", got)
	}
	release <- struct{}{}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stable lock inode removed: %v", err)
	}
}

func ageLock(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-2 * enqueueLockIdleAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

// Every enqueue left a lock file behind for good: dev had 881 after a week.
// Cleanup now removes the old ones nobody holds, and leaves the rest.
func TestCleanupPrunesIdleEnqueueLocks(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorageBackend(dir)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "tmp")
	lock := func(id string) (string, func()) {
		t.Helper()
		p := filepath.Join(tmp, ".enqueue-"+id)
		release, err := acquireEnqueueLock(p)
		if err != nil {
			t.Fatal(err)
		}
		return p, release
	}

	idle, release := lock("idle")
	release()
	ageLock(t, idle)
	held, releaseHeld := lock("held")
	defer releaseHeld()
	ageLock(t, held)
	fresh, release := lock("fresh")
	release()

	before, err := fs.Cleanup(24)
	if err != nil {
		t.Fatal(err)
	}
	if before != 0 {
		t.Errorf("cleanup counted %d messages; lock files aren't messages", before)
	}
	if _, err := os.Stat(idle); !os.IsNotExist(err) {
		t.Error("an old lock nobody holds survived cleanup")
	}
	if _, err := os.Stat(held); err != nil {
		t.Errorf("a held lock was removed: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a fresh lock was removed: %v", err)
	}
}

// A process that opened a lock file which is then pruned must not end up
// holding a lock on the removed inode while another holds one on its
// replacement: it notices and starts again on the current file, so the two
// still exclude each other.
func TestPrunedLockDoesNotSplitWaiters(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".enqueue-x")
	release, err := acquireEnqueueLock(path)
	if err != nil {
		t.Fatal(err)
	}
	release()

	// The race, step by step: a waiter has the old inode open...
	stale, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stale.Close() }()
	// ...pruning removes it...
	ageLock(t, path)
	if n, err := pruneEnqueueLocks(tmp, time.Now().Add(-enqueueLockIdleAge)); err != nil || n != 1 {
		t.Fatalf("prune removed %d, %v", n, err)
	}
	// ...and the old inode no longer counts as the lock.
	if current, err := lockIsCurrent(int(stale.Fd()), path); err != nil || current {
		t.Fatalf("a pruned lock file still counts as current (%v, %v)", current, err)
	}

	// The next acquirer gets a new file, and holding it excludes others.
	first, err := acquireEnqueueLock(path)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		second, err := acquireEnqueueLock(path)
		if err == nil {
			close(got)
			second()
		}
	}()
	select {
	case <-got:
		t.Fatal("a second acquirer got the lock while the first held it")
	case <-time.After(150 * time.Millisecond):
	}
	first()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the second acquirer never got the lock after it was released")
	}
}
