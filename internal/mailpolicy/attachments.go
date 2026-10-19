package mailpolicy

import (
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message"
)

// LargestAttachment returns the decoded size of the biggest attachment in a
// message, for the max_attachment_bytes limit. The mailbox (mail received)
// and the MTA (mail sent) both measure with this, so a limit means the same
// in both directions.
//
// An attachment is a non-multipart part sent as one (Content-Disposition:
// attachment) or carrying a file name. The size is after transfer decoding,
// because that is the file the user sees: base64 adds a third on the wire,
// and a limit of 10 MB should let a 10 MB file through. A forwarded message
// (message/rfc822) counts as one attachment of its full size. Parsing is
// bounded in depth and part count, and a message that can't be parsed has
// no attachments to measure; its total size is still limited separately.
func LargestAttachment(raw []byte) int64 {
	e, err := message.Read(bytes.NewReader(raw))
	if e == nil || err != nil && !message.IsUnknownCharset(err) {
		return 0
	}
	budget := 1000
	return largest(e, 0, &budget)
}

func largest(e *message.Entity, depth int, budget *int) int64 {
	*budget--
	if depth > 32 || *budget < 0 {
		return 0
	}
	if parts := e.MultipartReader(); parts != nil {
		var best int64
		for {
			part, err := parts.NextPart()
			if err != nil {
				return best
			}
			best = max(best, largest(part, depth+1, budget))
		}
	}
	disposition, dparams, _ := e.Header.ContentDisposition()
	typ, tparams, _ := e.Header.ContentType()
	isFile := strings.EqualFold(disposition, "attachment") || dparams["filename"] != "" || tparams["name"] != "" || strings.EqualFold(typ, "message/rfc822")
	if !isFile {
		return 0
	}
	n, _ := io.Copy(io.Discard, e.Body)
	return n
}
