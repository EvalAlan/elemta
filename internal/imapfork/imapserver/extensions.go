package imapserver

// Extensions added in this fork (see ../FORK.md):
//
//   - SORT (RFC 5256, with RFC 5957 DISPLAYFROM/DISPLAYTO)
//   - THREAD=REFERENCES and THREAD=ORDEREDSUBJECT (RFC 5256)
//   - QUOTA, read only: GETQUOTA and GETQUOTAROOT (RFC 9208)
//   - ID (RFC 2971)
//
// Each is advertised only when the session implements its interface.

import (
	"fmt"
	"strings"

	"github.com/EvalAlan/elemta/internal/imapfork/internal/imapwire"
	"github.com/emersion/go-imap/v2"
)

// SortKey is one SORT criterion, such as DATE or REVERSE SUBJECT.
type SortKey struct {
	Key     string // ARRIVAL, CC, DATE, FROM, SIZE, SUBJECT, TO, DISPLAYFROM, DISPLAYTO
	Reverse bool
}

// SessionSort is a session that supports SORT.
type SessionSort interface {
	Session
	// Sort returns the numbers (sequence or UID, as kind says) of the
	// messages matching criteria, in the requested order.
	Sort(kind NumKind, keys []SortKey, criteria *imap.SearchCriteria) ([]uint32, error)
}

// Thread is a node of a THREAD response. A node with Num 0 stands for a
// message that is referenced but missing, and has children.
type Thread struct {
	Num      uint32
	Children []Thread
}

// SessionThread is a session that supports THREAD.
type SessionThread interface {
	Session
	ThreadAlgorithms() []string
	Thread(kind NumKind, algorithm string, criteria *imap.SearchCriteria) ([]Thread, error)
}

// QuotaResource is one resource of a quota root, in the units RFC 9208
// uses (STORAGE in kibibytes, MESSAGE in messages).
type QuotaResource struct {
	Name         string
	Usage, Limit int64
}

// SessionQuota is a session that reports quotas.
type SessionQuota interface {
	Session
	QuotaRoots(mailbox string) ([]string, error)
	Quota(root string) ([]QuotaResource, error)
}

// SessionID is a session that answers ID.
type SessionID interface {
	Session
	// ID receives the client's identification (nil when it sent NIL) and
	// returns the server's.
	ID(client map[string]string) map[string]string
}

var sortKeys = map[string]bool{
	"ARRIVAL": true, "CC": true, "DATE": true, "FROM": true, "SIZE": true,
	"SUBJECT": true, "TO": true, "DISPLAYFROM": true, "DISPLAYTO": true,
}

// extensionCaps lists the capabilities this fork adds for the session.
func (c *Conn) extensionCaps() []imap.Cap {
	var caps []imap.Cap
	if _, ok := c.session.(SessionSort); ok {
		caps = append(caps, "SORT", "SORT=DISPLAY")
	}
	if t, ok := c.session.(SessionThread); ok {
		for _, alg := range t.ThreadAlgorithms() {
			caps = append(caps, imap.Cap("THREAD="+alg))
		}
	}
	if _, ok := c.session.(SessionCondStore); ok {
		caps = append(caps, imap.CapCondStore)
	}
	if _, ok := c.session.(SessionQResync); ok {
		caps = append(caps, imap.CapQResync)
	}
	if _, ok := c.session.(SessionQuota); ok {
		caps = append(caps, "QUOTA", "QUOTA=RES-STORAGE")
	}
	return caps
}

// readCharsetAndCriteria reads "SP charset SP search-key *(SP search-key)
// CRLF", the tail SORT and THREAD share. Only UTF-8 and US-ASCII are
// accepted, as for SEARCH.
func readCharsetAndCriteria(dec *imapwire.Decoder, criteria *imap.SearchCriteria) error {
	var charset string
	if !dec.ExpectSP() || !dec.ExpectAString(&charset) || !dec.ExpectSP() {
		return dec.Err()
	}
	switch strings.ToUpper(charset) {
	case "US-ASCII", "UTF-8":
	default:
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeBadCharset,
			Text: "Only US-ASCII and UTF-8 are supported charsets",
		}
	}
	for {
		if err := readSearchKey(criteria, dec); err != nil {
			return fmt.Errorf("in search-key: %w", err)
		}
		if !dec.SP() {
			break
		}
	}
	if !dec.ExpectCRLF() {
		return dec.Err()
	}
	return nil
}

func (c *Conn) handleSort(dec *imapwire.Decoder, numKind NumKind) error {
	session, ok := c.session.(SessionSort)
	if !ok {
		return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "Unknown command"}
	}
	if !dec.ExpectSP() {
		return dec.Err()
	}
	var keys []SortKey
	err := dec.ExpectList(func() error {
		var atom string
		if !dec.ExpectAtom(&atom) {
			return dec.Err()
		}
		key := SortKey{Key: strings.ToUpper(atom)}
		if key.Key == "REVERSE" {
			if !dec.ExpectSP() || !dec.ExpectAtom(&atom) {
				return dec.Err()
			}
			key = SortKey{Key: strings.ToUpper(atom), Reverse: true}
		}
		if !sortKeys[key.Key] {
			return newClientBugError("Unknown sort key " + key.Key)
		}
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return newClientBugError("Empty sort criteria")
	}
	var criteria imap.SearchCriteria
	if err := readCharsetAndCriteria(dec, &criteria); err != nil {
		return err
	}
	if err := c.checkState(imap.ConnStateSelected); err != nil {
		return err
	}
	nums, err := session.Sort(numKind, keys, &criteria)
	if err != nil {
		return err
	}
	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("SORT")
	for _, n := range nums {
		enc.SP().Number(n)
	}
	return enc.CRLF()
}

func (c *Conn) handleThread(dec *imapwire.Decoder, numKind NumKind) error {
	session, ok := c.session.(SessionThread)
	if !ok {
		return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "Unknown command"}
	}
	var algorithm string
	if !dec.ExpectSP() || !dec.ExpectAtom(&algorithm) {
		return dec.Err()
	}
	algorithm = strings.ToUpper(algorithm)
	supported := false
	for _, a := range session.ThreadAlgorithms() {
		if a == algorithm {
			supported = true
		}
	}
	if !supported {
		return newClientBugError("Unsupported thread algorithm " + algorithm)
	}
	var criteria imap.SearchCriteria
	if err := readCharsetAndCriteria(dec, &criteria); err != nil {
		return err
	}
	if err := c.checkState(imap.ConnStateSelected); err != nil {
		return err
	}
	threads, err := session.Thread(numKind, algorithm, &criteria)
	if err != nil {
		return err
	}
	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("THREAD")
	if len(threads) > 0 {
		enc.SP()
	}
	for _, t := range threads {
		writeThread(enc.Encoder, t)
	}
	return enc.CRLF()
}

// writeThread writes one parenthesised thread. A chain of single children
// is written flat ("(1 2 3)"); siblings are nested ("(1 (2)(3))").
func writeThread(enc *imapwire.Encoder, t Thread) {
	enc.Special('(')
	first := true
	node := t
	if node.Num != 0 {
		enc.Number(node.Num)
		first = false
	}
	for len(node.Children) == 1 && node.Children[0].Num != 0 {
		node = node.Children[0]
		if !first {
			enc.SP()
		}
		enc.Number(node.Num)
		first = false
	}
	if len(node.Children) > 0 {
		if !first {
			enc.SP()
		}
		for _, child := range node.Children {
			writeThread(enc, child)
		}
	}
	enc.Special(')')
}

func (c *Conn) handleGetQuotaRoot(dec *imapwire.Decoder) error {
	var mailbox string
	if !dec.ExpectSP() || !dec.ExpectMailbox(&mailbox) || !dec.ExpectCRLF() {
		return dec.Err()
	}
	if err := c.checkState(imap.ConnStateAuthenticated); err != nil {
		return err
	}
	session, ok := c.session.(SessionQuota)
	if !ok {
		return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "Unknown command"}
	}
	roots, err := session.QuotaRoots(mailbox)
	if err != nil {
		return err
	}
	enc := newResponseEncoder(c)
	enc.Atom("*").SP().Atom("QUOTAROOT").SP().Mailbox(mailbox)
	for _, r := range roots {
		enc.SP().String(r)
	}
	err = enc.CRLF()
	enc.end()
	if err != nil {
		return err
	}
	for _, r := range roots {
		if err := c.writeQuota(session, r); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) handleGetQuota(dec *imapwire.Decoder) error {
	var root string
	if !dec.ExpectSP() || !dec.ExpectAString(&root) || !dec.ExpectCRLF() {
		return dec.Err()
	}
	if err := c.checkState(imap.ConnStateAuthenticated); err != nil {
		return err
	}
	session, ok := c.session.(SessionQuota)
	if !ok {
		return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "Unknown command"}
	}
	return c.writeQuota(session, root)
}

func (c *Conn) writeQuota(session SessionQuota, root string) error {
	resources, err := session.Quota(root)
	if err != nil {
		return err
	}
	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("QUOTA").SP().String(root).SP().Special('(')
	for i, r := range resources {
		if i > 0 {
			enc.SP()
		}
		enc.Atom(r.Name).SP().Number64(r.Usage).SP().Number64(r.Limit)
	}
	enc.Special(')')
	return enc.CRLF()
}

func (c *Conn) handleID(dec *imapwire.Decoder) error {
	if !dec.ExpectSP() {
		return dec.Err()
	}
	var client map[string]string
	isList, err := dec.List(func() error {
		var k, v string
		if !dec.ExpectString(&k) || !dec.ExpectSP() || !dec.ExpectNString(&v) {
			return dec.Err()
		}
		if client == nil {
			client = map[string]string{}
		}
		if len(client) < 30 {
			client[k] = v
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !isList && !dec.ExpectNIL() {
		return dec.Err()
	}
	if !dec.ExpectCRLF() {
		return dec.Err()
	}
	var server map[string]string
	if s, ok := c.session.(SessionID); ok {
		server = s.ID(client)
	}
	enc := newResponseEncoder(c)
	defer enc.end()
	enc.Atom("*").SP().Atom("ID").SP()
	if len(server) == 0 {
		enc.NIL()
		return enc.CRLF()
	}
	enc.Special('(')
	first := true
	for _, k := range []string{"name", "version", "vendor", "support-url"} {
		v, ok := server[k]
		if !ok {
			continue
		}
		if !first {
			enc.SP()
		}
		enc.String(k).SP().String(v)
		first = false
	}
	enc.Special(')')
	return enc.CRLF()
}
