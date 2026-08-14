package queue

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The whole point: the same message is handled one at a time.
func TestSameMessageIsSerialized(t *testing.T) {
	var locks messageLocks
	var inside, maxInside int32

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := locks.acquire("same-id")
			defer release()
			n := atomic.AddInt32(&inside, 1)
			for {
				old := atomic.LoadInt32(&maxInside)
				if n <= old || atomic.CompareAndSwapInt32(&maxInside, old, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&inside, -1)
		}()
	}
	wg.Wait()

	if maxInside != 1 {
		t.Errorf("%d goroutines were inside the lock for one message at once, want 1", maxInside)
	}
}

// And the point of not using one global lock: different messages do not wait
// for each other. Serialized, 20 x 50ms is a second; concurrent, it is 50ms.
func TestDifferentMessagesRunConcurrently(t *testing.T) {
	var locks messageLocks

	var wg sync.WaitGroup
	began := time.Now()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			release := locks.acquire(string(rune('a' + n)))
			defer release()
			time.Sleep(50 * time.Millisecond)
		}(i)
	}
	wg.Wait()

	if elapsed := time.Since(began); elapsed > 500*time.Millisecond {
		t.Errorf("20 different messages took %v; they are serializing against "+
			"each other, which is the bottleneck this replaces", elapsed)
	}
}

// A map keyed by message id that only grows is the tombstone leak again.
func TestLockEntriesAreReleased(t *testing.T) {
	var locks messageLocks

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			release := locks.acquire(string(rune(n)))
			release()
		}(i)
	}
	wg.Wait()

	// Read the map directly rather than through a helper: a helper used only
	// by tests reads as dead code to the linter, and this test is in-package.
	locks.mu.Lock()
	held := len(locks.locks)
	locks.mu.Unlock()
	if held != 0 {
		t.Errorf("%d lock entries remain after every holder released; the map grows without bound", held)
	}
}
