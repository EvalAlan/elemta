package webmail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// MailWatcher owns its connections independently of the session's selected
// mailbox, so a long-lived IDLE never holds up ordinary mail requests.
type MailWatcher func(context.Context, string, string, string, chan<- struct{}, chan<- struct{}) error

func watchIMAP(cfg Config) MailWatcher {
	return func(ctx context.Context, user, password, folder string, changed, ready chan<- struct{}) error {
		signal := func() {
			select {
			case changed <- struct{}{}:
			default:
			}
		}
		st, err := dialIMAPUpdates(ctx, cfg, user, password, &imapclient.UnilateralDataHandler{
			Mailbox: func(*imapclient.UnilateralDataMailbox) { signal() },
			Expunge: func(uint32) { signal() },
			Fetch: func(msg *imapclient.FetchMessageData) {
				for msg.Next() != nil {
				}
				signal()
			},
		})
		if err != nil {
			return err
		}
		// Closing the socket interrupts setup, IDLE and a failed server's reads.
		stop := context.AfterFunc(ctx, func() { _ = st.c.Close() })
		defer stop()
		defer func() { _ = st.c.Close() }()
		if !st.c.Caps().Has(imap.CapIdle) && !st.c.Caps().Has(imap.CapIMAP4rev2) {
			return errors.New("webmail: IMAP server does not support IDLE")
		}
		if _, err := st.c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
			return err
		}
		idle, err := st.c.Idle()
		if err != nil {
			return err
		}
		select {
		case ready <- struct{}{}:
		case <-ctx.Done():
		}
		select {
		case <-ctx.Done():
		case <-st.c.Closed():
		}
		_ = idle.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("webmail: IDLE connection closed")
	}
}

func (s *Server) mailEvents(w http.ResponseWriter, r *http.Request, sess *Session) {
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming unavailable", http.StatusNotImplemented)
		return
	}
	// Bound connections even when a browser keeps opening new tabs.
	s.pushMu.Lock()
	if s.pushStreams == nil {
		s.pushStreams = make(map[string]int)
	}
	if s.pushStreams[sess.ID] >= 3 {
		s.pushMu.Unlock()
		http.Error(w, "too many streams", http.StatusTooManyRequests)
		return
	}
	s.pushStreams[sess.ID]++
	s.pushMu.Unlock()
	defer func() {
		s.pushMu.Lock()
		s.pushStreams[sess.ID]--
		if s.pushStreams[sess.ID] == 0 {
			delete(s.pushStreams, sess.ID)
		}
		s.pushMu.Unlock()
	}()
	pw, err := s.sessions.password(sess)
	if err != nil {
		http.Error(w, "signed out", http.StatusUnauthorized)
		return
	}
	// End before the HTTP server's write timeout. EventSource reconnects and
	// reauthenticates, including after logout, expiry or an administrator reset.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	changed := make(chan struct{}, 1)
	failed := make(chan error, 2)
	ready := make(chan struct{}, 2)
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "INBOX"
	}
	watcher := s.watch
	if watcher == nil {
		watcher = watchIMAP(s.cfg)
	}
	folders := []string{"INBOX"}
	if folder != "INBOX" {
		folders = append(folders, folder)
	}
	for _, name := range folders {
		go func() { failed <- watcher(ctx, sess.User, pw, name, changed, ready) }()
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	send := func(event string) error {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: {}\n\n", event); err != nil {
			return err
		}
		return rc.Flush()
	}
	if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
		return
	}
	if rc.Flush() != nil {
		return
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	var eventTimer *time.Timer
	var eventTick <-chan time.Time
	defer func() {
		if eventTimer != nil {
			eventTimer.Stop()
		}
	}()
	started := 0
	for {
		select {
		case <-ready:
			started++
			if started == len(folders) && send("ready") != nil {
				return
			}
		case <-ctx.Done():
			return
		case err := <-failed:
			// Logged so a mailbox that keeps dropping push is diagnosable;
			// the page falls back to polling either way.
			s.log.Debug("webmail: mail push stopped", "user", sess.User, "error", err)
			_ = send("unavailable")
			return
		case <-changed:
			if eventTick == nil {
				eventTimer = time.NewTimer(200 * time.Millisecond)
				eventTick = eventTimer.C
			}
		case <-eventTick:
			eventTick = nil
			if send("mail") != nil {
				return
			}
		case <-heartbeat.C:
			if _, ok := s.sessions.Get(sess.ID); !ok {
				_ = send("signedout")
				return
			}
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}
