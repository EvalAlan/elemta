package webmail

import (
	"bufio"
	"context"
	"net/http"
	"strings"
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
