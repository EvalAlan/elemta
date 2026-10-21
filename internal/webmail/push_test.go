package webmail

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIMAPIdleArrivalAndCancellation(t *testing.T) {
	cfg := startIMAP(t)
	writer := dialTest(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed, ready := make(chan struct{}, 1), make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- watchIMAP(cfg)(ctx, "dana@example.com", "secret", "INBOX", changed, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("watch startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("IDLE startup timed out")
	}
	// Drain SELECT notifications, then delivery must produce another event.
	for {
		select {
		case <-changed:
		default:
			goto drained
		}
	}
drained:
	appendTo(t, writer, "INBOX", testMessage(1, "Push delivery"))
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery did not trigger IDLE")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("IDLE connection leaked after cancel")
	}
}

func TestMailEventsStreamsAndDisconnects(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.server.push.linger = 10 * time.Millisecond
	started, ended := make(chan string, 2), make(chan string, 2)
	trigger := make(chan struct{}, 1)
	h.server.watch = func(ctx context.Context, _, _, folder string, changed, ready chan<- struct{}) error {
		started <- folder
		ready <- struct{}{}
		defer func() { ended <- folder }()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-trigger:
				changed <- struct{}{}
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", h.srv.URL+"/api/events?folder=Projects", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("stream headers missing")
	}
	reader := bufio.NewReader(resp.Body)
	nextEvent := func() string {
		t.Helper()
		for {
			line, e := reader.ReadString('\n')
			if e != nil {
				t.Fatal(e)
			}
			if strings.HasPrefix(line, "event: ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "event: "))
			}
		}
	}
	if nextEvent() != "ready" {
		t.Fatal("missing ready event")
	}
	a, b := <-started, <-started
	if a == b || (a != "INBOX" && b != "INBOX") {
		t.Fatalf("watched %q and %q", a, b)
	}
	trigger <- struct{}{}
	if nextEvent() != "mail" {
		t.Fatal("missing mail event")
	}
	_ = resp.Body.Close()
	cancel()
	for range 2 {
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Fatal("watcher leaked")
		}
	}
}

// Each page opens a stream; one IMAP connection serves them all while the
// user clicks around, and closes once they stop.
func TestMailEventsShareOneWatch(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.server.push.linger = 300 * time.Millisecond
	var mu sync.Mutex
	starts := 0
	ended := make(chan struct{}, 4)
	h.server.watch = func(ctx context.Context, _, _, _ string, _, ready chan<- struct{}) error {
		mu.Lock()
		starts++
		mu.Unlock()
		ready <- struct{}{}
		<-ctx.Done()
		ended <- struct{}{}
		return ctx.Err()
	}
	page := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", h.srv.URL+"/api/events", nil)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(line, "event: ready") {
				return
			}
		}
	}
	for range 3 {
		page()
	}
	mu.Lock()
	n := starts
	mu.Unlock()
	if n != 1 {
		t.Fatalf("%d IMAP watches for three pages, want 1", n)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("shared watch never closed after the last page")
	}
}

// A shared connection stops taking new streams once it is old enough, so it
// reauthenticates the way an unshared stream did.
func TestPushHubRetiresOldWatch(t *testing.T) {
	hub := &pushHub{linger: time.Hour, share: 50 * time.Millisecond}
	var mu sync.Mutex
	starts := 0
	w := hub.wrap(func(ctx context.Context, _, _, _ string, _, ready chan<- struct{}) error {
		mu.Lock()
		starts++
		mu.Unlock()
		ready <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	run := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() { done <- w(ctx, "u", "p", "INBOX", make(chan struct{}, 1), ready) }()
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("not ready")
		}
		return cancel, done
	}
	c1, d1 := run()
	time.Sleep(60 * time.Millisecond)
	c2, d2 := run()
	mu.Lock()
	n := starts
	mu.Unlock()
	if n != 2 {
		t.Fatalf("starts = %d, want a fresh watch after the share window", n)
	}
	c1()
	c2()
	<-d1
	<-d2
}
