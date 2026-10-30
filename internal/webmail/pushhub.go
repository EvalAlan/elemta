package webmail

import (
	"context"
	"sync"
	"time"
)

// pushKey identifies a shared watch.
type pushKey struct{ user, password, folder string }

// pushHub shares one IDLE connection per user and folder between the live
// update streams of that user's pages.
//
// The webmail renders pages on the server, so every click loads a new page,
// and every page opens a new stream. Without sharing, each one cost a fresh
// IMAP login (a directory bind and the account lookups) and a SELECT, which
// reads every UID and flag in the folder, only to be torn down on the next
// click. The load suite measured about one of those per webmail action,
// the largest single cost of a page view on the mailbox side.
//
// A watch lingers briefly after its last stream closes so the next page
// picks it up, and stops taking new streams after pushMaxShare so a
// connection still reauthenticates every few minutes, as an unshared stream
// did: a changed password, a reset or a disabled account ends push within
// pushMaxShare plus a stream's own lifetime.
type pushHub struct {
	mu      sync.Mutex
	watches map[pushKey]*pushWatch
	linger  time.Duration
	share   time.Duration
}

const (
	pushLinger   = 30 * time.Second
	pushMaxShare = 3 * time.Minute
)

type pushWatch struct {
	born    time.Time
	cancel  context.CancelFunc
	subs    map[*pushSub]struct{}
	ready   bool
	done    chan struct{} // closed when the watcher returns
	err     error
	retired bool // no longer in the hub's map
	idle    *time.Timer
}

type pushSub struct {
	changed chan<- struct{}
	ready   chan<- struct{}
}

func signalOnce(c chan<- struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// wrap returns a MailWatcher that shares the connections of underlying.
func (h *pushHub) wrap(underlying MailWatcher) MailWatcher {
	return func(ctx context.Context, user, password, folder string, changed, ready chan<- struct{}) error {
		// The password is in the key so that a session holding a different
		// one never rides on another's authentication. It is held here
		// anyway, by the watch that has to log in with it.
		key := pushKey{user, password, folder}
		sub := &pushSub{changed: changed, ready: ready}
		w := h.join(key, sub, func(wctx context.Context, wchanged, wready chan<- struct{}) error {
			return underlying(wctx, user, password, folder, wchanged, wready)
		})
		select {
		case <-ctx.Done():
			h.leave(key, w, sub)
			return ctx.Err()
		case <-w.done:
			return w.err
		}
	}
}

func (h *pushHub) join(key pushKey, sub *pushSub, start func(context.Context, chan<- struct{}, chan<- struct{}) error) *pushWatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.watches == nil {
		h.watches = map[pushKey]*pushWatch{}
	}
	share := h.share
	if share == 0 {
		share = pushMaxShare
	}
	w := h.watches[key]
	if w != nil && time.Since(w.born) >= share {
		// Old enough to reauthenticate: new streams get a new connection,
		// and this one closes when its last stream does.
		w.retired = true
		delete(h.watches, key)
		if len(w.subs) == 0 {
			w.cancel()
		}
		w = nil
	}
	if w == nil {
		ctx, cancel := context.WithCancel(context.Background())
		w = &pushWatch{born: time.Now(), cancel: cancel, subs: map[*pushSub]struct{}{}, done: make(chan struct{})}
		h.watches[key] = w
		changed := make(chan struct{}, 1)
		ready := make(chan struct{}, 1)
		go func() {
			err := start(ctx, changed, ready)
			h.mu.Lock()
			w.err = err
			if !w.retired {
				w.retired = true
				delete(h.watches, key)
			}
			if w.idle != nil {
				w.idle.Stop()
			}
			h.mu.Unlock()
			cancel()
			close(w.done)
		}()
		go func() {
			for {
				select {
				case <-w.done:
					return
				case <-ready:
					h.mu.Lock()
					w.ready = true
					for s := range w.subs {
						signalOnce(s.ready)
					}
					h.mu.Unlock()
				case <-changed:
					h.mu.Lock()
					for s := range w.subs {
						signalOnce(s.changed)
					}
					h.mu.Unlock()
				}
			}
		}()
	}
	if w.idle != nil {
		w.idle.Stop()
		w.idle = nil
	}
	w.subs[sub] = struct{}{}
	if w.ready {
		signalOnce(sub.ready)
	}
	return w
}

func (h *pushHub) leave(key pushKey, w *pushWatch, sub *pushSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(w.subs, sub)
	if len(w.subs) > 0 {
		return
	}
	if w.retired {
		w.cancel()
		return
	}
	linger := h.linger
	if linger == 0 {
		linger = pushLinger
	}
	var t *time.Timer
	t = time.AfterFunc(linger, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		// A stream that joined and left again since has its own timer.
		if len(w.subs) > 0 || w.idle != t {
			return
		}
		if !w.retired {
			w.retired = true
			delete(h.watches, key)
		}
		w.cancel()
	})
	w.idle = t
}
