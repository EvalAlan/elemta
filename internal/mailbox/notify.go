package mailbox

// Change notifications for idle sessions.
//
// An IMAP session in IDLE has to notice when its folder changes: new mail,
// another client's flags or expunges. Asking the database once a second
// per session made idle connections the largest load on Postgres: a
// quarter of a million phones and desktop clients holding IDLE open is a
// quarter of a million queries a second, nearly all of them answering
// "nothing changed".
//
// Instead, a trigger on mailbox_folders (schema.sql) sends a Postgres
// notification whenever a folder's MODSEQ moves, from any process and
// any code path (delivery, IMAP, the webmail, restores). Each mailbox
// server holds one LISTEN connection and wakes only the sessions watching
// that folder. Postgres folds identical notifications in one transaction
// into one and delivers them only on commit, so a session never wakes to
// a change it can't yet see.
//
// Notifications can be lost when the LISTEN connection drops. The hub
// then wakes every watcher once it is back, and sessions also check on
// their own every few minutes, so a missed notification costs latency,
// never a missed message. Without a working listener, sessions fall back
// to checking every second, as before.

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"
)

const (
	// folderChannel is the Postgres notification channel (schema.sql).
	folderChannel = "elemta_folder"
	// idleFallback is about how often an idle session checks without being
	// woken. Notifications are lost only when the LISTEN connection drops,
	// and reconnecting wakes everyone, so this is a backstop; it is long
	// because each check is a query, and spread out (fallbackJitter) so
	// sessions that started together don't keep checking together.
	idleFallback   = 5 * time.Minute
	fallbackJitter = time.Minute
	// idlePollUnwatched is the old per-second check, used while the hub
	// has no live LISTEN connection.
	idlePollUnwatched = time.Second
)

// folderHub fans folder-change notifications out to the sessions watching
// each folder.
type folderHub struct {
	log     *slog.Logger
	mu      sync.Mutex
	watch   map[int64]map[chan struct{}]struct{}
	live    atomic.Bool
	wakeups atomic.Int64
}

func newFolderHub(log *slog.Logger) *folderHub {
	return &folderHub{log: log, watch: map[int64]map[chan struct{}]struct{}{}}
}

// subscribe returns a channel that receives (without blocking the hub)
// when folder changes, and a function to stop watching.
func (h *folderHub) subscribe(folder int64) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	set := h.watch[folder]
	if set == nil {
		set = map[chan struct{}]struct{}{}
		h.watch[folder] = set
	}
	set[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if set := h.watch[folder]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(h.watch, folder)
			}
		}
		h.mu.Unlock()
	}
}

// interval is how long an idle session waits between its own checks.
func (h *folderHub) interval() time.Duration {
	if h != nil && h.live.Load() {
		return idleFallback + rand.N(fallbackJitter)
	}
	return idlePollUnwatched
}

func (h *folderHub) wake(folder int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.watch[folder] {
		h.signal(ch)
	}
}

func (h *folderHub) wakeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, set := range h.watch {
		for ch := range set {
			h.signal(ch)
		}
	}
}

func (h *folderHub) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
		h.wakeups.Add(1)
	default: // already due to check
	}
}

// watching is the number of sessions watching some folder.
func (h *folderHub) watching() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, set := range h.watch {
		n += len(set)
	}
	return n
}

// notification is what the hub needs from a LISTEN connection; pq's
// Listener provides it.
type notificationSource interface {
	NotificationChannel() <-chan *pq.Notification
	Listen(channel string) error
	Close() error
}

// run holds the LISTEN connection until ctx ends.
func (h *folderHub) run(ctx context.Context, dsn string) {
	if dsn == "" {
		return
	}
	connected := make(chan struct{}, 1)
	l := pq.NewListener(dsn, time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		switch ev {
		case pq.ListenerEventConnected, pq.ListenerEventReconnected:
			select {
			case connected <- struct{}{}:
			default:
			}
		case pq.ListenerEventDisconnected, pq.ListenerEventConnectionAttemptFailed:
			if h.live.Swap(false) && err != nil {
				h.log.Warn("mailbox: change notifications lost; idle sessions check every second until they're back", "error", err)
			}
		}
	})
	h.serve(ctx, l, connected)
}

func (h *folderHub) serve(ctx context.Context, l notificationSource, connected <-chan struct{}) {
	defer func() { _ = l.Close() }()
	if err := l.Listen(folderChannel); err != nil {
		h.log.Warn("mailbox: change notifications unavailable; idle sessions check every second", "error", err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			h.live.Store(false)
			return
		case <-connected:
			// (Re)connected: anything sent while away is lost, so everyone
			// checks once.
			if !h.live.Swap(true) {
				h.log.Info("mailbox: change notifications on")
			}
			h.wakeAll()
		case n, ok := <-l.NotificationChannel():
			if !ok {
				h.live.Store(false)
				return
			}
			if n == nil {
				// pq sends nil after reconnecting.
				h.wakeAll()
				continue
			}
			id, err := strconv.ParseInt(n.Extra, 10, 64)
			if err != nil {
				continue
			}
			h.wake(id)
		}
	}
}
