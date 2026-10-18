package imapserver

// CONDSTORE and QRESYNC (RFC 7162), added in this fork (see ../FORK.md).
//
// CONDSTORE gives every message a modification sequence (MODSEQ), so a
// client can ask for only what changed since it last looked (FETCH
// CHANGEDSINCE) and make flag changes conditional on nothing having
// changed meanwhile (STORE UNCHANGEDSINCE). QRESYNC adds resynchronising a
// mailbox in the SELECT itself, and reports expunges as VANISHED UIDs
// rather than sequence numbers. Phones and desktop clients use both to
// avoid refetching every message's flags on reconnect.

import (
	"strings"

	"github.com/EvalAlan/elemta/internal/imapfork/internal/imapwire"
	"github.com/emersion/go-imap/v2"
)

// SessionCondStore is a session that keeps per-message MODSEQs. Its
// SelectData.HighestModSeq and StatusData.HighestModSeq are reported, its
// Fetch honours FetchOptions.ModSeq and ChangedSince, its Store honours
// StoreOptions.UnchangedSince (failing messages reported with
// NewModifiedError), and its Search honours SearchCriteria.ModSeq.
type SessionCondStore interface {
	Session
	CondStore()
}

// QResyncParams are the QRESYNC parameters of a SELECT or EXAMINE.
type QResyncParams struct {
	UIDValidity uint32
	ModSeq      uint64
	// KnownUIDs is what the client holds; empty means every UID.
	KnownUIDs imap.UIDSet
}

// SessionQResync is a session that resynchronises in SELECT.
type SessionQResync interface {
	SessionCondStore
	// QResync is called after a successful SELECT with QRESYNC. When the
	// UIDVALIDITY matches, it reports what changed since ModSeq: VANISHED
	// (EARLIER) for expunged UIDs, then FETCH (UID FLAGS MODSEQ) for
	// messages changed.
	QResync(w *FetchWriter, params *QResyncParams) error
}

// NewModifiedError reports the messages a STORE UNCHANGEDSINCE left alone
// because they changed since, in the tagged OK (RFC 7162 3.1.3).
func NewModifiedError(set imap.NumSet) error {
	return &imap.Error{Type: imap.StatusResponseTypeOK, Code: imap.ResponseCode("MODIFIED " + set.String()), Text: "Conditional STORE failed for some messages"}
}

func (c *Conn) condStoreSupported() bool {
	_, ok := c.session.(SessionCondStore)
	return ok
}

func (c *Conn) qresyncSupported() bool {
	_, ok := c.session.(SessionQResync)
	return ok
}

// enableCondStore records a CONDSTORE-enabling command (RFC 7162 3.1).
func (c *Conn) enableCondStore() {
	c.mutex.Lock()
	c.enabled[imap.CapCondStore] = struct{}{}
	c.mutex.Unlock()
}

func (c *Conn) condStoreEnabled() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.enabled.Has(imap.CapCondStore)
}

func (c *Conn) qresyncEnabled() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.enabled.Has(imap.CapQResync)
}

// readSelectParams reads the optional SELECT parameter list.
func readSelectParams(dec *imapwire.Decoder) (condStore bool, qresync *QResyncParams, err error) {
	if !dec.SP() {
		return false, nil, nil
	}
	err = dec.ExpectList(func() error {
		var name string
		if !dec.ExpectAtom(&name) {
			return dec.Err()
		}
		switch strings.ToUpper(name) {
		case "CONDSTORE":
			condStore = true
		case "QRESYNC":
			qresync = &QResyncParams{}
			if !dec.ExpectSP() {
				return dec.Err()
			}
			return dec.ExpectList(func() error {
				if !dec.ExpectNumber(&qresync.UIDValidity) || !dec.ExpectSP() || !dec.ExpectModSeq(&qresync.ModSeq) {
					return dec.Err()
				}
				if dec.SP() {
					if !dec.ExpectUIDSet(&qresync.KnownUIDs) {
						return dec.Err()
					}
					// The optional sequence match data only speeds up the
					// server's work; it is read and not needed.
					if dec.SP() {
						return dec.ExpectList(func() error {
							var s string
							if !dec.ExpectAtom(&s) {
								return dec.Err()
							}
							return nil
						})
					}
				}
				return nil
			})
		default:
			return newClientBugError("Unknown SELECT parameter " + name)
		}
		return nil
	})
	return condStore, qresync, err
}

// readFetchModifiers reads "(CHANGEDSINCE n [VANISHED])" after a FETCH.
func readFetchModifiers(dec *imapwire.Decoder, options *imap.FetchOptions) (vanished bool, err error) {
	if !dec.SP() {
		return false, nil
	}
	err = dec.ExpectList(func() error {
		var name string
		if !dec.ExpectAtom(&name) {
			return dec.Err()
		}
		switch strings.ToUpper(name) {
		case "CHANGEDSINCE":
			if !dec.ExpectSP() || !dec.ExpectModSeq(&options.ChangedSince) {
				return dec.Err()
			}
			options.ModSeq = true
		case "VANISHED":
			vanished = true
		default:
			return newClientBugError("Unknown FETCH modifier " + name)
		}
		return nil
	})
	return vanished, err
}

// readStoreModifiers reads "(UNCHANGEDSINCE n) " before a STORE item.
func readStoreModifiers(dec *imapwire.Decoder, options *imap.StoreOptions) (bool, error) {
	isList, err := dec.List(func() error {
		var name string
		if !dec.ExpectAtom(&name) {
			return dec.Err()
		}
		if !strings.EqualFold(name, "UNCHANGEDSINCE") {
			return newClientBugError("Unknown STORE modifier " + name)
		}
		if !dec.ExpectSP() || !dec.ExpectModSeq(&options.UnchangedSince) {
			return dec.Err()
		}
		return nil
	})
	if err != nil || !isList {
		return isList, err
	}
	if !dec.ExpectSP() {
		return true, dec.Err()
	}
	return true, nil
}

// readSearchModSeq reads the MODSEQ search key's arguments.
func readSearchModSeq(dec *imapwire.Decoder, criteria *imap.SearchCriteria) error {
	if !dec.ExpectSP() {
		return dec.Err()
	}
	ms := &imap.SearchCriteriaModSeq{}
	var name string
	if dec.Quoted(&name) {
		var typ string
		if !dec.ExpectSP() || !dec.ExpectAtom(&typ) || !dec.ExpectSP() {
			return dec.Err()
		}
		ms.MetadataName, ms.MetadataType = name, imap.SearchCriteriaMetadataType(strings.ToLower(typ))
	}
	if !dec.ExpectModSeq(&ms.ModSeq) {
		return dec.Err()
	}
	criteria.ModSeq = ms
	return nil
}

// usesModSeq reports whether a search tree has a MODSEQ key.
func usesModSeq(c *imap.SearchCriteria) bool {
	if c.ModSeq != nil {
		return true
	}
	for i := range c.Not {
		if usesModSeq(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if usesModSeq(&c.Or[i][0]) || usesModSeq(&c.Or[i][1]) {
			return true
		}
	}
	return false
}

func (c *Conn) writeHighestModSeq(n uint64) error {
	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("OK").SP()
	enc.Special('[').Atom("HIGHESTMODSEQ").SP().ModSeq(n).Special(']')
	enc.SP().Text("Highest")
	return enc.CRLF()
}

func (c *Conn) writeVanished(uids imap.UIDSet, earlier bool) error {
	if len(uids) == 0 {
		return nil
	}
	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("VANISHED").SP()
	if earlier {
		enc.Atom("(EARLIER)").SP()
	}
	enc.NumSet(uids)
	return enc.CRLF()
}

// writeExpungeUID reports an expunge: as VANISHED once QRESYNC is enabled
// (RFC 7162 3.2.10), as EXPUNGE otherwise.
func (c *Conn) writeExpungeUID(seqNum uint32, uid imap.UID) error {
	if c.qresyncEnabled() {
		var set imap.UIDSet
		set.AddNum(uid)
		return c.writeVanished(set, false)
	}
	return c.writeExpunge(seqNum)
}

// CondStore reports whether responses should carry MODSEQ.
func (w *FetchWriter) CondStore() bool { return w.conn != nil && w.conn.condStoreEnabled() }

// Vanished reports whether a UID FETCH asked for VANISHED (QRESYNC).
func (w *FetchWriter) Vanished() bool { return w.vanished }

// WriteVanished reports UIDs expunged earlier, for FETCH VANISHED and
// QRESYNC.
func (w *FetchWriter) WriteVanished(uids imap.UIDSet) error { return w.conn.writeVanished(uids, true) }

// WriteModSeq writes the message's MODSEQ.
func (w *FetchResponseWriter) WriteModSeq(n uint64) {
	w.writeItemSep()
	w.enc.Atom("MODSEQ").SP().Special('(').ModSeq(n).Special(')')
}

// WriteExpungeUID writes an expunge as EXPUNGE or, under QRESYNC, VANISHED.
func (w *ExpungeWriter) WriteExpungeUID(seqNum uint32, uid imap.UID) error {
	if w.conn == nil {
		return nil
	}
	return w.conn.writeExpungeUID(seqNum, uid)
}

// WriteExpungeUID writes an expunge as EXPUNGE or, under QRESYNC, VANISHED.
func (w *MoveWriter) WriteExpungeUID(seqNum uint32, uid imap.UID) error {
	return w.conn.writeExpungeUID(seqNum, uid)
}

// WriteExpungeUID writes an expunge as EXPUNGE or, under QRESYNC, VANISHED.
func (w *UpdateWriter) WriteExpungeUID(seqNum uint32, uid imap.UID) error {
	if !w.allowExpunge {
		return w.WriteExpunge(seqNum) // reports the error
	}
	return w.conn.writeExpungeUID(seqNum, uid)
}

// WriteMessageFlagsModSeq is WriteMessageFlags with the MODSEQ that
// CONDSTORE clients expect in unsolicited flag updates.
func (w *UpdateWriter) WriteMessageFlagsModSeq(seqNum uint32, uid imap.UID, flags []imap.Flag, modSeq uint64) error {
	fetchWriter := &FetchWriter{conn: w.conn}
	respWriter := fetchWriter.CreateMessage(seqNum)
	if uid != 0 {
		respWriter.WriteUID(uid)
	}
	respWriter.WriteFlags(flags)
	if modSeq != 0 && w.conn.condStoreEnabled() {
		respWriter.WriteModSeq(modSeq)
	}
	return respWriter.Close()
}
