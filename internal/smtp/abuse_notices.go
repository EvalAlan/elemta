package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/queue"
)

// SendAbuseNotices emails the administrators the alerts and holds the abuse
// engine queues (internal/abuse/notify.go), until ctx ends. They go through
// the queue like any mail this server sends, so they're DKIM-signed, retried
// and visible on the queue page.
func (s *Server) SendAbuseNotices(ctx context.Context) {
	if s.abuse == nil || s.queueManager == nil {
		return
	}
	s.abuse.DeliverNotices(ctx, func(_ context.Context, to []string, n abuse.Notice) error {
		from := "postmaster@" + s.noticeDomain()
		_, err := s.queueManager.EnqueueMessage(from, to, n.Subject, noticeMessage(from, s.config.Hostname, to, n), queue.PriorityHigh, time.Now())
		return err
	})
}

// noticeDomain is the domain notices come from: the first local domain,
// which is one this server signs for, or the host name without one.
func (s *Server) noticeDomain() string {
	if s.config != nil {
		for _, domain := range s.config.LocalDomains {
			if domain = strings.TrimSpace(domain); domain != "" {
				return strings.ToLower(domain)
			}
		}
		if s.config.Hostname != "" {
			return s.config.Hostname
		}
	}
	return "localhost"
}

func noticeMessage(from, hostname string, to []string, n abuse.Notice) []byte {
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: Elemta <%s>\r\n", from)
	fmt.Fprintf(&b, "To: <%s>\r\n", strings.Join(to, ">, <"))
	fmt.Fprintf(&b, "Date: %s\r\n", n.Time.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", n.Subject))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), hostname)
	// No vacation replies or other robots answering a robot (RFC 3834).
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(n.Body, "\n", "\r\n")))
	_ = qp.Close()
	return b.Bytes()
}
