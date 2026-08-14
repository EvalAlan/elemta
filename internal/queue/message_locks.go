package queue

import "sync"

// messageLocks serializes work on the same message without serializing work on
// different ones.
//
// DeleteMessage used to hold the manager's single mutex across three file
// operations — read the metadata, read the whole message body, then write a
// tombstone and unlink. Every delivery in the server queued behind that one
// lock. Measured on a 52,000-message queue with 20 workers configured: LMTP
// itself took 33ms at the median, yet only 0.9 workers were ever busy and the
// queue drained at 11 messages a second with every container under 7% CPU.
// Nineteen workers were blocked on a mutex held across disk reads.
//
// Deletes of different messages touch different files and different rows and
// have never needed to exclude each other. Deletes of the *same* message do,
// and that is what this provides.
//
// Entries are reference-counted and removed when the last holder leaves. A map
// keyed by message id that only ever grows is the same shape as the tombstone
// leak this queue already had once.
type messageLocks struct {
	mu    sync.Mutex
	locks map[string]*messageLock
}

type messageLock struct {
	mu   sync.Mutex
	refs int
}

// acquire blocks until this id is free, and returns the release function.
func (ml *messageLocks) acquire(id string) func() {
	ml.mu.Lock()
	if ml.locks == nil {
		ml.locks = make(map[string]*messageLock)
	}
	lock, ok := ml.locks[id]
	if !ok {
		lock = &messageLock{}
		ml.locks[id] = lock
	}
	// Counted while the registry lock is held, so the entry cannot be removed
	// between finding it here and taking it below.
	lock.refs++
	ml.mu.Unlock()

	lock.mu.Lock()

	return func() {
		lock.mu.Unlock()
		ml.mu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(ml.locks, id)
		}
		ml.mu.Unlock()
	}
}
