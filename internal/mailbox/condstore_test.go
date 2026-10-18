package mailbox

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// rawIMAP is a minimal line client, so tests see the exact wire format.
type rawIMAP struct {
	t   *testing.T
	c   net.Conn
	r   *bufio.Reader
	tag int
}

func dialRaw(t *testing.T, addr string) *rawIMAP {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	r := &rawIMAP{t: t, c: c, r: bufio.NewReader(c)}
	_, _ = r.r.ReadString('\n') // greeting
	return r
}

// cmd sends a command and returns the untagged lines and the tagged line.
func (r *rawIMAP) cmd(format string, args ...any) ([]string, string) {
	r.t.Helper()
	r.tag++
	tag := fmt.Sprintf("a%d", r.tag)
	_ = r.c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(r.c, "%s %s\r\n", tag, fmt.Sprintf(format, args...))
	var lines []string
	for {
		line, err := r.r.ReadString('\n')
		if err != nil {
			r.t.Fatalf("%s: %v (got %q)", format, err, lines)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return lines, line
		}
		lines = append(lines, line)
	}
}

func joined(lines []string) string { return strings.Join(lines, "\n") }

func TestCondStoreAndQResync(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	var uids []uint32
	for i := 0; i < 4; i++ {
		res, err := e.Append(ctx, a.ID, "INBOX", []byte(fmt.Sprintf("Subject: m%d\r\n\r\nx\r\n", i)), nil, time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		uids = append(uids, res.UID)
	}
	_, addr, _ := startTestService(t, e, a)
	c := dialRaw(t, addr)
	if _, ok := c.cmd("LOGIN %s testpass", a.Address); !strings.Contains(ok, "OK") {
		t.Fatal(ok)
	}
	lines, _ := c.cmd("CAPABILITY")
	if !strings.Contains(joined(lines), "CONDSTORE") || !strings.Contains(joined(lines), "QRESYNC") {
		t.Fatalf("capabilities = %s", joined(lines))
	}
	if lines, ok := c.cmd("ENABLE QRESYNC"); !strings.Contains(joined(lines), "QRESYNC") || !strings.Contains(ok, "OK") {
		t.Fatalf("ENABLE = %s %s", joined(lines), ok)
	}
	lines, ok := c.cmd("SELECT INBOX (CONDSTORE)")
	m := regexp.MustCompile(`HIGHESTMODSEQ (\d+)`).FindStringSubmatch(joined(lines))
	if m == nil || !strings.Contains(ok, "OK") {
		t.Fatalf("SELECT = %s %s", joined(lines), ok)
	}
	var base uint64
	fmt.Sscan(m[1], &base)
	validity := regexp.MustCompile(`UIDVALIDITY (\d+)`).FindStringSubmatch(joined(lines))[1]

	// MODSEQ in FETCH, and CHANGEDSINCE returning only later changes.
	lines, _ = c.cmd("UID FETCH 1:* (FLAGS MODSEQ)")
	if len(lines) != 4 || !strings.Contains(lines[0], "MODSEQ (") {
		t.Fatalf("FETCH MODSEQ = %s", joined(lines))
	}
	c.cmd("UID STORE %d +FLAGS.SILENT (\\Flagged)", uids[1])
	lines, _ = c.cmd("UID FETCH 1:* (FLAGS) (CHANGEDSINCE %d)", base)
	if len(lines) != 1 || !strings.Contains(lines[0], fmt.Sprintf("UID %d", uids[1])) || !strings.Contains(lines[0], "MODSEQ") {
		t.Fatalf("CHANGEDSINCE = %s", joined(lines))
	}

	// UNCHANGEDSINCE refuses a stale change and says which with MODIFIED.
	lines, ok = c.cmd("UID STORE %d,%d (UNCHANGEDSINCE %d) +FLAGS (\\Seen)", uids[1], uids[2], base)
	if !strings.Contains(ok, fmt.Sprintf("[MODIFIED %d]", uids[1])) {
		t.Fatalf("UNCHANGEDSINCE = %s / %s", joined(lines), ok)
	}
	if !strings.Contains(joined(lines), fmt.Sprintf("UID %d", uids[2])) {
		t.Fatalf("the unchanged message wasn't stored: %s", joined(lines))
	}

	// SEARCH MODSEQ reports the highest MODSEQ found.
	lines, _ = c.cmd("UID SEARCH MODSEQ %d", base+1)
	if !strings.Contains(joined(lines), "(MODSEQ ") {
		t.Fatalf("SEARCH MODSEQ = %s", joined(lines))
	}
	lines, _ = c.cmd("STATUS INBOX (HIGHESTMODSEQ)")
	if !strings.Contains(joined(lines), "HIGHESTMODSEQ") {
		t.Fatalf("STATUS = %s", joined(lines))
	}

	// An expunge elsewhere, then a QRESYNC SELECT from the old state:
	// VANISHED (EARLIER) for the gone UID and the changed flags.
	if err := e.MutateFlags(ctx, a.ID, "INBOX", []uint32{uids[3]}, []string{"\\deleted"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{uids[3]}); err != nil {
		t.Fatal(err)
	}
	c2 := dialRaw(t, addr)
	c2.cmd("LOGIN %s testpass", a.Address)
	c2.cmd("ENABLE QRESYNC")
	lines, ok = c2.cmd("SELECT INBOX (QRESYNC (%s %d))", validity, base)
	all := joined(lines)
	if !strings.Contains(all, fmt.Sprintf("VANISHED (EARLIER) %d", uids[3])) || !strings.Contains(all, fmt.Sprintf("UID %d", uids[1])) || !strings.Contains(ok, "OK") {
		t.Fatalf("QRESYNC SELECT = %s / %s", all, ok)
	}

	// With QRESYNC on, a live expunge is reported as VANISHED.
	c.cmd("UID STORE %d +FLAGS.SILENT (\\Deleted)", uids[0])
	lines, _ = c.cmd("EXPUNGE")
	if !strings.Contains(joined(lines), fmt.Sprintf("VANISHED %d", uids[0])) || strings.Contains(joined(lines), "EXPUNGE") {
		t.Fatalf("EXPUNGE under QRESYNC = %s", joined(lines))
	}

	// After the journal is trimmed, VANISHED falls back to the UIDs in
	// range that no longer exist.
	if _, err := e.DB.Exec(`UPDATE mailbox_changes SET created=now()-interval '30 days' WHERE folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name='INBOX')`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CompactChanges(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	c3 := dialRaw(t, addr)
	c3.cmd("LOGIN %s testpass", a.Address)
	c3.cmd("ENABLE QRESYNC")
	lines, _ = c3.cmd("SELECT INBOX (QRESYNC (%s %d %d:%d))", validity, base, uids[0], uids[3])
	all = joined(lines)
	if !strings.Contains(all, "VANISHED (EARLIER)") || !strings.Contains(all, fmt.Sprint(uids[3])) {
		t.Fatalf("QRESYNC after compaction = %s", all)
	}
}
