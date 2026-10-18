package imapserver

import (
	"github.com/EvalAlan/elemta/internal/imapfork/internal"
	"github.com/EvalAlan/elemta/internal/imapfork/internal/imapwire"
	"github.com/emersion/go-imap/v2"
)

func (c *Conn) handleEnable(dec *imapwire.Decoder) error {
	var requested []imap.Cap
	for dec.SP() {
		cap, err := internal.ExpectCap(dec)
		if err != nil {
			return err
		}
		requested = append(requested, cap)
	}
	if !dec.ExpectCRLF() {
		return dec.Err()
	}

	if err := c.checkState(imap.ConnStateAuthenticated); err != nil {
		return err
	}

	var enabled []imap.Cap
	for _, req := range requested {
		switch req {
		case imap.CapIMAP4rev2, imap.CapUTF8Accept:
			enabled = append(enabled, req)
		case imap.CapCondStore:
			if c.condStoreSupported() {
				enabled = append(enabled, req)
			}
		case imap.CapQResync:
			// QRESYNC implies CONDSTORE (RFC 7162 3.2.3).
			if c.qresyncSupported() {
				enabled = append(enabled, req, imap.CapCondStore)
			}
		}
	}

	c.mutex.Lock()
	for _, e := range enabled {
		c.enabled[e] = struct{}{}
	}
	c.mutex.Unlock()

	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("ENABLED")
	for _, c := range enabled {
		enc.SP().Atom(string(c))
	}
	return enc.CRLF()
}
