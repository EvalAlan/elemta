package mailbox

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// A refused non-synchronizing literal ({n+}) leaves the client's bytes on the
// wire unread, so the server must close the connection rather than parse them
// as commands (RFC 7888 §4).
func TestRefusedNonSyncLiteralClosesTheConnection(t *testing.T) {
	e, a := testEngine(t)
	_, addr, _ := startTestService(t, e, a)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatal(err)
	}
	send := func(s string) {
		if _, err := conn.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	readTagged := func(tag string) string {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return "<" + err.Error() + ">"
			}
			if strings.HasPrefix(line, tag+" ") {
				return line
			}
		}
	}
	send("a LOGIN " + a.Address + " testpass\r\n")
	if reply := readTagged("a"); !strings.HasPrefix(reply, "a OK") {
		t.Fatalf("login: %q", reply)
	}
	// An APPEND far over the limit, as a non-synchronizing literal, whose
	// "data" is a command the server must never run.
	send("b APPEND INBOX {999999999999+}\r\nc LOGOUT\r\n")
	if reply := readTagged("b"); !strings.HasPrefix(reply, "b NO") {
		t.Fatalf("oversized APPEND: %q", reply)
	}
	if reply := readTagged("c"); strings.HasPrefix(reply, "c ") {
		t.Fatalf("literal data was run as a command: %q", reply)
	}
}
