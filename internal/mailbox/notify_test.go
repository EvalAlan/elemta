package mailbox

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/lib/pq"
)

type fakeNotifications struct {
	ch     chan *pq.Notification
	closed bool
}

func (f *fakeNotifications) NotificationChannel() <-chan *pq.Notification { return f.ch }
func (f *fakeNotifications) Listen(string) error                          { return nil }
func (f *fakeNotifications) Close() error                                 { f.closed = true; return nil }

func TestFolderHubWakesWatchers(t *testing.T) {
	h := newFolderHub(slog.Default())
	if h.interval() != idlePollUnwatched {
		t.Fatal("without a listener, sessions should check every second")
	}
	src := &fakeNotifications{ch: make(chan *pq.Notification, 4)}
	connected := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.serve(ctx, src, connected); close(done) }()

	inbox, stopInbox := h.subscribe(7)
	other, stopOther := h.subscribe(8)
	defer stopOther()
	connected <- struct{}{}
	// Connecting wakes everyone: anything sent before is lost.
	for _, ch := range []<-chan struct{}{inbox, other} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("connecting didn't wake a watcher")
		}
	}
	if i := h.interval(); i < idleFallback || i > idleFallback+fallbackJitter {
		t.Fatal("with a listener, sessions should only check now and then")
	}
	src.ch <- &pq.Notification{Channel: folderChannel, Extra: "7"}
	select {
	case <-inbox:
	case <-time.After(time.Second):
		t.Fatal("a change to folder 7 didn't wake its watcher")
	}
	select {
	case <-other:
		t.Fatal("a change to folder 7 woke folder 8's watcher")
	case <-time.After(50 * time.Millisecond):
	}
	// Many changes before the session looks wake it once, not once each.
	for range 3 {
		src.ch <- &pq.Notification{Channel: folderChannel, Extra: "7"}
	}
	time.Sleep(50 * time.Millisecond)
	if len(inbox) != 1 {
		t.Fatalf("pending wakeups = %d, want 1", len(inbox))
	}
	<-inbox
	// pq sends nil after reconnecting: everyone checks.
	src.ch <- nil
	for _, ch := range []<-chan struct{}{inbox, other} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("a reconnect didn't wake a watcher")
		}
	}
	stopInbox()
	if h.watching() != 1 {
		t.Fatalf("watching = %d after one unsubscribed", h.watching())
	}
	cancel()
	<-done
	if !src.closed || h.interval() != idlePollUnwatched {
		t.Error("stopping should close the listener and go back to polling")
	}
}

// A session idling on one mailbox server hears about mail appended through
// another at once, from the notification, not from its backstop check.
func TestIdleWokenByNotification(t *testing.T) {
	e, a := testEngine(t)
	service, addr, _ := startTestService(t, e, a)
	go service.folders.run(service.ctx, os.Getenv("ELEMTA_TEST_MAILBOX_DSN"))
	waitFor(t, "the listener", func() bool { return service.folders.live.Load() })

	updates := make(chan uint32, 8)
	c, err := imapclient.DialInsecure(addr, &imapclient.Options{UnilateralDataHandler: &imapclient.UnilateralDataHandler{Mailbox: func(data *imapclient.UnilateralDataMailbox) {
		if data.NumMessages != nil {
			updates <- *data.NumMessages
		}
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	idle, err := c.Idle()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the session to watch INBOX", func() bool { return service.folders.watching() == 1 })
	raw := []byte("From: a@example.com\r\nSubject: hi\r\n\r\nhello\r\n")
	start := time.Now()
	if _, err := e.Append(context.Background(), a.ID, "INBOX", raw, nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-updates:
		if n != 1 {
			t.Fatalf("EXISTS %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IDLE didn't hear about the new message")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("IDLE took %v: woken by its fallback check, not the notification", took)
	}
	if err := idle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := idle.Wait(); err != nil {
		t.Fatal(err)
	}
	if service.folders.watching() != 0 {
		t.Error("the session still watches INBOX after IDLE ended")
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestIdleLoad measures what idle sessions cost the database, with and
// without notifications. It is a measurement, not a check, so it runs
// only when asked: ELEMTA_IDLE_LOAD=<sessions>.
func TestIdleLoad(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ELEMTA_IDLE_LOAD"))
	if n == 0 {
		t.Skip("set ELEMTA_IDLE_LOAD to a number of idle sessions to measure")
	}
	dsn := os.Getenv("ELEMTA_TEST_MAILBOX_DSN")
	e, a := testEngine(t)
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Limits.MaxConnections = n + 100
	stats, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stats.Close() }()
	commits := func() int64 {
		var v int64
		if err := stats.QueryRow(`SELECT xact_commit+xact_rollback FROM pg_stat_database WHERE datname=current_database()`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// One account per session, as real users idle on their own mailboxes.
	accounts := make([]Account, n)
	auth := mapAuth{}
	for i := range accounts {
		accounts[i] = Account{ID: fmt.Sprintf("%s-%d", a.ID, i), Address: fmt.Sprintf("load%d-%s", i, a.Address)}
		if err := e.EnsureAccount(context.Background(), accounts[i]); err != nil {
			t.Fatal(err)
		}
		auth[accounts[i].Address] = accounts[i]
	}
	t.Cleanup(func() {
		for _, acc := range accounts {
			_, _ = e.DB.Exec(`DELETE FROM mailbox_deliveries WHERE account=$1`, acc.ID)
			_, _ = e.DB.Exec(`DELETE FROM mailbox_folders WHERE account=$1`, acc.ID)
			_, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, acc.ID)
		}
	})
	for _, notified := range []bool{false, true} {
		service, addr, _ := startTestService(t, e, a, cfg)
		service.auth = auth
		if notified {
			go service.folders.run(service.ctx, dsn)
			waitFor(t, "the listener", func() bool { return service.folders.live.Load() })
		}
		clients := make([]*imapclient.Client, n)
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := range clients {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := imapclient.DialInsecure(addr, nil)
				if err != nil {
					errs <- err
					return
				}
				clients[i] = c
				if err := c.Login(accounts[i].Address, "testpass").Wait(); err != nil {
					errs <- err
					return
				}
				if _, err := c.Select("INBOX", nil).Wait(); err != nil {
					errs <- err
					return
				}
				if _, err := c.Idle(); err != nil {
					errs <- err
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		if os.Getenv("ELEMTA_IDLE_LOAD_STATEMENTS") != "" {
			_, _ = stats.Exec(`SELECT pg_stat_statements_reset()`)
		}
		before := commits()
		const window = 10 * time.Second
		// One delivery a second, so the sessions have something to see.
		raw := []byte("From: a@example.com\r\nSubject: load\r\n\r\nhello\r\n")
		for i := range int(window / time.Second) {
			if _, err := e.Append(context.Background(), accounts[i%n].ID, "INBOX", raw, nil, time.Now(), ""); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
		}
		perSecond := float64(commits()-before) / window.Seconds()
		t.Logf("%d idle sessions, notifications %v: %.0f database transactions a second", n, notified, perSecond)
		fmt.Fprintf(os.Stderr, "IDLE-LOAD sessions=%d notified=%v tx_per_s=%.0f\n", n, notified, perSecond)
		if os.Getenv("ELEMTA_IDLE_LOAD_STATEMENTS") != "" {
			rows, err := stats.Query(`SELECT calls, left(regexp_replace(query, '\s+', ' ', 'g'), 110) FROM pg_stat_statements ORDER BY calls DESC LIMIT 6`)
			if err == nil {
				for rows.Next() {
					var calls int64
					var q string
					_ = rows.Scan(&calls, &q)
					fmt.Fprintf(os.Stderr, "  %7d  %s\n", calls, q)
				}
				_ = rows.Close()
			}
		}
		for _, c := range clients {
			if c != nil {
				_ = c.Close()
			}
		}
		service.cancel()
		time.Sleep(time.Second)
	}
}

// mapAuth signs in any of a set of accounts with the test password.
type mapAuth map[string]Account

func (m mapAuth) Login(_ context.Context, u, p string) (Account, error) {
	a, ok := m[u]
	if !ok || p != "testpass" {
		return Account{}, ErrCredentials
	}
	return a, nil
}
func (m mapAuth) Exists(_ context.Context, u string) (bool, error) { _, ok := m[u]; return ok, nil }
func (m mapAuth) Resolve(_ context.Context, u string) (Account, error) {
	a, ok := m[u]
	if !ok {
		return Account{}, ErrCredentials
	}
	return a, nil
}
