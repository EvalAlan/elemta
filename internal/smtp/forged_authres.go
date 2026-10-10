package smtp

import (
	"bytes"
	"io"
	"strings"

	"github.com/EvalAlan/elemta/internal/queue"
)

// Forged Authentication-Results headers.
//
// This server writes an Authentication-Results header naming itself as the
// authserv-id, and mail clients and filters downstream trust a header with
// that id because it is supposed to come from here. A sender can put one in
// the message already, claiming dkim=pass for a forged From. RFC 8601 §5
// requires a border MTA to remove or rename any that claim to be from it.
//
// They are renamed, not removed, and to a name of exactly the same length, so
// the stored message is the received message byte for byte apart from those
// names: the size accounting, the streaming from the spool and any
// signatures over other headers are all unaffected. Only headers inside the
// bounded head the server already reads are examined.

const (
	authResultsName  = "Authentication-Results"
	renamedAuthNames = "X-Untrusted-AuthResult" // same length as authResultsName
)

// neutralizeForgedAuthResults returns head with every Authentication-Results
// header whose authserv-id is hostname renamed, and whether any was.
func neutralizeForgedAuthResults(head []byte, hostname string) ([]byte, bool) {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if hostname == "" || len(authResultsName) != len(renamedAuthNames) {
		return head, false
	}
	end := bytes.Index(head, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(head)
	}

	var out []byte
	for pos := 0; pos < end; {
		lineEnd := bytes.Index(head[pos:end], []byte("\r\n"))
		if lineEnd < 0 {
			lineEnd = end - pos
		}
		line := head[pos : pos+lineEnd]
		if isForgedAuthResults(line, hostname) {
			if out == nil {
				out = append([]byte(nil), head...)
			}
			copy(out[pos:], renamedAuthNames)
		}
		pos += lineEnd + 2
	}
	if out == nil {
		return head, false
	}
	return out, true
}

func isForgedAuthResults(line []byte, hostname string) bool {
	name, value, ok := bytes.Cut(line, []byte(":"))
	if !ok || !strings.EqualFold(string(bytes.TrimRight(name, " \t")), authResultsName) {
		return false
	}
	// The authserv-id is the first token, before ';' (RFC 8601 §2.2), with
	// optional whitespace and a version number after it.
	id := string(value)
	if i := strings.IndexByte(id, ';'); i >= 0 {
		id = id[:i]
	}
	fields := strings.Fields(id)
	if len(fields) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(fields[0], "."), hostname)
}

// withPatchedHead returns an opener whose first len(head) bytes are patched
// and the rest is body unchanged.
func withPatchedHead(body queue.ContentOpener, head, patched []byte) queue.ContentOpener {
	return func() (io.ReadCloser, error) {
		r, err := body()
		if err != nil {
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, r, int64(len(head))); err != nil {
			_ = r.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(patched), r), r}, nil
	}
}
