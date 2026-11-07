//go:build cells

package mailbox

// End to end against two cells and the router on the dev cluster
// (scripts/k8s-cells-dev.sh up): go test -tags cells -run TestCells ./internal/mailbox/
// ELEMTA_CELLS_IDLE sets how many idle sessions the load check holds.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-smtp"
)

const cellsNS = "elemta-cells"

func cellsSecret(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deployments", "compose", ".secrets", "cells", name))
	if err != nil {
		t.Skipf("no cells dev stack (scripts/k8s-cells-dev.sh up): %v", err)
	}
	return strings.TrimSpace(string(b))
}

func cellsTLS(t *testing.T) *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(cellsSecret(t, "cert.pem")))
	return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// psql runs a query in a cell's database and returns its single value.
func psql(t *testing.T, cell, query string) string {
	t.Helper()
	out, err := exec.Command("kubectl", "-n", cellsNS, "exec", "pg-"+cell+"-0", "--", "psql", "-U", "mailbox", "-d", "mailbox", "-Atc", query).CombinedOutput()
	if err != nil {
		t.Fatalf("psql %s: %v %s", cell, err, out)
	}
	return strings.TrimSpace(string(out))
}

func messagesIn(t *testing.T, cell, address string) int {
	n, _ := strconv.Atoi(psql(t, cell, `SELECT count(*) FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder JOIN mailbox_accounts a ON a.id=f.account WHERE a.address='`+address+`'`))
	return n
}

func cellsIMAP(t *testing.T, user string) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialTLS("127.0.0.1:21993", &imapclient.Options{TLSConfig: cellsTLS(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(user, cellsSecret(t, "user-password")).Wait(); err != nil {
		t.Fatalf("%s: %v", user, err)
	}
	return c
}

func TestCellsEndToEnd(t *testing.T) {
	users := map[string]string{"alice@a.test": "a", "carol@a.test": "a", "bob@b.test": "b", "dave@c.test": "a"}
	before := map[string]int{}
	for u, cell := range users {
		before[u] = messagesIn(t, cell, u)
	}

	// One delivery to all four, and one to nobody, through the router.
	conn, err := net.Dial("tcp", "127.0.0.1:21424")
	if err != nil {
		t.Fatal(err)
	}
	lc := smtp.NewClientLMTP(conn)
	if err := lc.Hello("e2e"); err != nil {
		t.Fatal(err)
	}
	if err := lc.Mail("sender@example.net", nil); err != nil {
		t.Fatal(err)
	}
	for u := range users {
		if err := lc.Rcpt(u, nil); err != nil {
			t.Fatalf("RCPT %s: %v", u, err)
		}
	}
	if err := lc.Rcpt("nobody@b.test", nil); err == nil {
		t.Error("nobody@b.test was accepted")
	}
	w, err := lc.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "From: sender@example.net\r\nSubject: hello cells\r\n\r\nacross cells\r\n")
	if replies, err := w.CloseWithLMTPResponse(); err != nil || len(replies) != len(users) {
		t.Fatalf("delivery: %v %v", replies, err)
	}
	_ = lc.Quit()
	for u, cell := range users {
		if got := messagesIn(t, cell, u); got != before[u]+1 {
			t.Errorf("%s: %d messages in cell %s, want %d", u, got, cell, before[u]+1)
		}
		other := map[string]string{"a": "b", "b": "a"}[cell]
		if got := messagesIn(t, other, u); got != 0 {
			t.Errorf("%s has %d messages in cell %s too", u, got, other)
		}
	}

	// Each signs in through the router and sees their own mail.
	for u := range users {
		c := cellsIMAP(t, u)
		st, err := c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
		if err != nil || int(*st.NumMessages) != before[u]+1 {
			t.Errorf("%s: %v %v", u, st, err)
		}
		_ = c.Logout().Wait()
	}

	// Move carol to cell b: same UIDVALIDITY and UIDs, through the router.
	c := cellsIMAP(t, "carol@a.test")
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	uids, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Logout().Wait()
	out, err := exec.Command("../../scripts/k8s-cells-dev.sh", "move", "carol@a.test", "b").CombinedOutput()
	if err != nil {
		t.Fatalf("move: %v\n%s", err, out)
	}
	t.Logf("move:\n%s", out)
	if messagesIn(t, "a", "carol@a.test") != 0 || messagesIn(t, "b", "carol@a.test") != before["carol@a.test"]+1 {
		t.Errorf("after the move: %d in a, %d in b", messagesIn(t, "a", "carol@a.test"), messagesIn(t, "b", "carol@a.test"))
	}
	c = cellsIMAP(t, "carol@a.test")
	moved, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	movedUIDs, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Logout().Wait()
	if moved.UIDValidity != sel.UIDValidity || fmt.Sprint(movedUIDs.AllUIDs()) != fmt.Sprint(uids.AllUIDs()) {
		t.Errorf("UIDVALIDITY %d -> %d, UIDs %v -> %v", sel.UIDValidity, moved.UIDValidity, uids.AllUIDs(), movedUIDs.AllUIDs())
	}
	// New mail for carol now goes to cell b.
	conn, err = net.Dial("tcp", "127.0.0.1:21424")
	if err != nil {
		t.Fatal(err)
	}
	lc = smtp.NewClientLMTP(conn)
	if err := lc.Hello("e2e"); err != nil {
		t.Fatal(err)
	}
	if err := lc.Mail("x@example.net", nil); err != nil {
		t.Fatal(err)
	}
	if err := lc.Rcpt("carol@a.test", nil); err != nil {
		t.Fatalf("delivery after the move: %v", err)
	}
	w, err = lc.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "Subject: after\r\n\r\nx\r\n")
	if _, err := w.CloseWithLMTPResponse(); err != nil {
		t.Fatal(err)
	}
	_ = lc.Quit()
	if got := messagesIn(t, "b", "carol@a.test"); got != before["carol@a.test"]+2 {
		t.Errorf("carol has %d messages in cell b after new mail", got)
	}
}

// TestCellsIdleLoad holds idle sessions through the router and counts
// what they cost the cells' databases.
func TestCellsIdleLoad(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ELEMTA_CELLS_IDLE"))
	if n == 0 {
		n = 1000
	}
	users := []string{"alice@a.test", "bob@b.test", "dave@c.test"}
	pw := cellsSecret(t, "user-password")
	for _, cell := range []string{"a", "b"} {
		psql(t, cell, `CREATE EXTENSION IF NOT EXISTS pg_stat_statements`)
	}
	clients := make([]*imapclient.Client, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	sem := make(chan struct{}, 50)
	for i := range clients {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fail := func(err error) { mu.Lock(); failures = append(failures, err); mu.Unlock() }
			c, err := imapclient.DialInsecure("127.0.0.1:21143", nil)
			if err != nil {
				fail(err)
				return
			}
			clients[i] = c
			if err := c.Login(users[i%len(users)], pw).Wait(); err != nil {
				fail(err)
				return
			}
			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				fail(err)
				return
			}
			if _, err := c.Idle(); err != nil {
				fail(err)
			}
		}(i)
	}
	wg.Wait()
	defer func() {
		for _, c := range clients {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	if len(failures) > 0 {
		t.Fatalf("%d of %d sessions failed, first: %v", len(failures), n, failures[0])
	}
	time.Sleep(3 * time.Second)
	const folderQuery = `SELECT coalesce(sum(calls),0) FROM pg_stat_statements WHERE query LIKE '%FROM mailbox_folders WHERE%'`
	for _, cell := range []string{"a", "b"} {
		psql(t, cell, `SELECT pg_stat_statements_reset()`)
	}
	window := 20 * time.Second
	time.Sleep(window)
	for _, cell := range []string{"a", "b"} {
		calls, _ := strconv.Atoi(psql(t, cell, folderQuery))
		conns := psql(t, cell, `SELECT count(*) FROM pg_stat_activity WHERE datname='mailbox'`)
		t.Logf("cell %s: %d idle sessions' folder queries in %s (%.1f a second), %s database connections", cell, calls, window, float64(calls)/window.Seconds(), conns)
		fmt.Fprintf(os.Stderr, "CELLS-IDLE cell=%s sessions=%d folder_queries_per_s=%.1f db_conns=%s\n", cell, n, float64(calls)/window.Seconds(), conns)
		// Once a second each, as before, would be about n/2 a second per cell.
		if float64(calls)/window.Seconds() > float64(n)/100 {
			t.Errorf("cell %s: idle sessions still poll (%d folder queries in %s)", cell, calls, window)
		}
	}
}
