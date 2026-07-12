//go:build linux

package queue

import (
	"os"
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
