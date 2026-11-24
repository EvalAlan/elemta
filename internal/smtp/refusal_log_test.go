package smtp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A refused command is one WARN line. The command handler and the session
// each used to log it ("SMTP command processed" and "SMTP command refused"),
// and the security check a third time for a malformed verb, so scanners on
// port 25 filled the warnings with copies.
func TestRefusedCommandIsLoggedOnce(t *testing.T) {
	logs := &lockedBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	server, client := net.Pipe()
	defer client.Close()
	session := NewSession(t.Context(), server, &Config{Hostname: "mx.example", Timeouts: TimeoutConfig{SessionTimeout: 10 * time.Second}}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_ = session.Handle()
	}()

	r := bufio.NewReader(client)
	reply := func() string {
		t.Helper()
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		var last string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("reading reply: %v", err)
			}
			last = strings.TrimRight(line, "\r\n")
			if len(last) < 4 || last[3] != '-' {
				return last
			}
		}
	}
	send := func(cmd string) string {
		t.Helper()
		_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := client.Write([]byte(cmd + "\r\n")); err != nil {
			t.Fatalf("writing %q: %v", cmd, err)
		}
		return reply()
	}

	reply() // greeting
	if got := send("EHLO client.example"); !strings.HasPrefix(got, "250") {
		t.Fatalf("EHLO: %s", got)
	}
	refused := 0
	for _, cmd := range []string{"AUTH PLAIN AGJvYgBwdw==", "G&T /", "RCPT TO:<a@example.com>"} {
		got := send(cmd)
		if got[0] != '4' && got[0] != '5' {
			t.Fatalf("%q was accepted: %s", cmd, got)
		}
		refused++
	}
	send("QUIT")
	<-done

	counts := map[string]int{}
	for _, l := range strings.Split(logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["level"] != "WARN" {
			continue
		}
		counts[m["msg"].(string)]++
	}
	if counts["SMTP command refused"] != refused {
		t.Errorf("%d refusals, %d \"SMTP command refused\" lines; want one each:\n%s", refused, counts["SMTP command refused"], logs.String())
	}
	for _, dup := range []string{"SMTP command processed", "Command name contains invalid characters"} {
		if counts[dup] != 0 {
			t.Errorf("%q logged at WARN %d times; the refusal line already says it", dup, counts[dup])
		}
	}
}
