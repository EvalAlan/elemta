package mailbox

import (
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"
)

func bodySection(raw []byte, section *imap.FetchItemBodySection) []byte {
	if len(section.Part) == 0 && section.Specifier == imap.PartSpecifierNone && len(section.HeaderFields) == 0 && len(section.HeaderFieldsNot) == 0 {
		// A raw download must preserve even damaged headers byte for byte.
		if section.Partial == nil {
			return raw
		}
		offset := min(max(section.Partial.Offset, 0), int64(len(raw)))
		size := min(max(section.Partial.Size, 0), int64(len(raw))-offset)
		return raw[offset : offset+size]
	}
	return imapserver.ExtractBodySection(bytes.NewReader(raw), section)
}

// Bound nesting before calling the protocol library's recursive extractor.
// Unusual or damaged mail remains downloadable as its original opaque bytes.
func bodyStructure(raw []byte) imap.BodyStructure {
	e, _ := message.Read(bytes.NewReader(raw))
	budget := 1000
	if e == nil || !boundedMIME(e, 0, &budget) {
		return &imap.BodyStructureSinglePart{Type: "application", Subtype: "octet-stream", Encoding: "binary", Size: seqNumber(len(raw)), Extended: &imap.BodyStructureSinglePartExt{}}
	}
	return imapserver.ExtractBodyStructure(bytes.NewReader(raw))
}
func boundedMIME(e *message.Entity, depth int, budget *int) bool {
	*budget--
	if depth > 32 || *budget < 0 {
		return false
	}
	if parts := e.MultipartReader(); parts != nil {
		for {
			part, err := parts.NextPart()
			if err == io.EOF {
				return true
			}
			if err != nil || !boundedMIME(part, depth+1, budget) {
				return false
			}
		}
	}
	typ, _, _ := e.Header.ContentType()
	if strings.EqualFold(typ, "message/rfc822") {
		child, _ := message.Read(e.Body)
		return child != nil && boundedMIME(child, depth+1, budget)
	}
	return true
}
