package webmail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
)

// Collection is one kind of non-mail object the webmail keeps for a user:
// calendar events, contacts, tasks, settings.
//
// Objects live in the user's own IMAP account, one message per object, in a
// folder per collection. That needs no database or extra service, the data
// is covered by the same login, quota and backups as the mail, and webmail
// pods stay stateless. The handlers only see the ObjectStore interface, so a
// SQL-backed store (which CalDAV/CardDAV sync will want) can replace this
// one without touching them.
type Collection string

// The collections, named after the IMAP folder that holds each one.
const (
	CollCalendar Collection = "Calendar"
	CollContacts Collection = "Contacts"
	CollTasks    Collection = "Tasks"
	CollSettings Collection = "Settings"
)

var collections = []Collection{CollCalendar, CollContacts, CollTasks, CollSettings}

// isObjectFolder reports whether an IMAP folder holds objects rather than
// mail, so the mail folder tree can leave it out.
func isObjectFolder(name string) bool {
	for _, c := range collections {
		if strings.EqualFold(name, string(c)) {
			return true
		}
	}
	return false
}

// Object is one stored item: an iCalendar event or task, a vCard, or a
// settings document.
type Object struct {
	ID          string
	Title       string // shown as the message subject in other mail clients
	ContentType string
	Data        []byte
	Modified    time.Time
}

// ObjectStore keeps a user's objects. Implementations must treat IDs as
// opaque, case-sensitive strings.
type ObjectStore interface {
	// Objects returns every object in the collection; an empty or missing
	// collection is not an error.
	Objects(ctx context.Context, c Collection) ([]Object, error)
	// PutObject creates or replaces the object with obj.ID.
	PutObject(ctx context.Context, c Collection, obj Object) error
	// DeleteObject removes an object; deleting a missing one is not an error.
	DeleteObject(ctx context.Context, c Collection, id string) error
}

// objectHeader marks a message as a stored object and carries its ID.
const objectHeader = "X-Elemta-Object"

// objectCache is one collection as last read, valid while the folder's
// UIDVALIDITY, UIDNEXT and message count are unchanged. Any append or
// expunge, by this session or another, changes one of them.
type objectCache struct {
	validity uint32
	next     imap.UID
	count    uint32
	objects  []Object
	uids     map[string][]imap.UID // object ID to the messages holding it
}

// objectID returns an ID safe for a header value. IDs from imported
// calendars can be any length and contain anything, so long or unusual ones
// are replaced by a hash, which stays stable for the same input.
func objectID(id string) string {
	ok := len(id) > 0 && len(id) <= 200
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			ok = false
			break
		}
	}
	if ok {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return "h-" + hex.EncodeToString(sum[:16])
}

func (s *imapStore) loadObjects(c Collection) (*objectCache, error) {
	status, err := s.c.Status(string(c), &imap.StatusOptions{NumMessages: true, UIDNext: true, UIDValidity: true}).Wait()
	if err != nil {
		if isNo(err) {
			return &objectCache{uids: map[string][]imap.UID{}}, nil // no folder yet
		}
		return nil, fmt.Errorf("webmail: status %q: %w", c, err)
	}
	count := uint32(0)
	if status.NumMessages != nil {
		count = *status.NumMessages
	}
	if cached := s.objects[c]; cached != nil && cached.validity == status.UIDValidity && cached.next == status.UIDNext && cached.count == count {
		return cached, nil
	}
	cache := &objectCache{validity: status.UIDValidity, next: status.UIDNext, count: count, uids: map[string][]imap.UID{}}
	if count > 0 {
		if _, err := s.selectFolder(string(c)); err != nil {
			return nil, err
		}
		section := &imap.FetchItemBodySection{Peek: true}
		var all imap.SeqSet
		all.AddRange(1, 0)
		msgs, err := s.c.Fetch(all, &imap.FetchOptions{UID: true, InternalDate: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
		if err != nil {
			return nil, fmt.Errorf("webmail: fetch %q: %w", c, err)
		}
		latest := map[string]int{}
		for _, m := range msgs {
			obj, err := decodeObject(m.FindBodySection(section))
			if err != nil {
				continue // not one of ours, or damaged: leave it alone
			}
			if obj.Modified.IsZero() {
				obj.Modified = m.InternalDate
			}
			cache.uids[obj.ID] = append(cache.uids[obj.ID], m.UID)
			// A crash between appending a new version and removing the old
			// one leaves two; the newest UID wins.
			if i, ok := latest[obj.ID]; ok {
				cache.objects[i] = obj
				continue
			}
			latest[obj.ID] = len(cache.objects)
			cache.objects = append(cache.objects, obj)
		}
	}
	s.objects[c] = cache
	return cache, nil
}

func (s *imapStore) Objects(ctx context.Context, c Collection) ([]Object, error) {
	cache, err := s.loadObjects(c)
	if err != nil {
		return nil, err
	}
	out := make([]Object, len(cache.objects))
	copy(out, cache.objects)
	return out, nil
}

func (s *imapStore) PutObject(ctx context.Context, c Collection, obj Object) error {
	obj.ID = objectID(obj.ID)
	cache, err := s.loadObjects(c)
	if err != nil {
		return err
	}
	old := cache.uids[obj.ID]
	raw, err := encodeObject(obj, time.Now())
	if err != nil {
		return err
	}
	if err := s.ensureFolder(string(c)); err != nil {
		return err
	}
	// Append first, then remove the old version: a failure in between
	// leaves a duplicate (resolved on read), never a lost object.
	if _, err := s.appendRaw(string(c), raw, []imap.Flag{imap.FlagSeen}); err != nil {
		return err
	}
	if len(old) > 0 {
		uids := make([]uint32, 0, len(old))
		for _, u := range old {
			uids = append(uids, uint32(u))
		}
		if err := s.expunge(string(c), uids); err != nil {
			return err
		}
	}
	return nil
}

func (s *imapStore) DeleteObject(ctx context.Context, c Collection, id string) error {
	cache, err := s.loadObjects(c)
	if err != nil {
		return err
	}
	old := cache.uids[objectID(id)]
	if len(old) == 0 {
		return nil
	}
	uids := make([]uint32, 0, len(old))
	for _, u := range old {
		uids = append(uids, uint32(u))
	}
	return s.expunge(string(c), uids)
}

// encodeObject wraps an object in a message. The data is base64 encoded, so
// any bytes survive IMAP intact.
func encodeObject(obj Object, now time.Time) ([]byte, error) {
	var h mail.Header
	h.SetDate(now)
	h.SetAddressList("From", []*mail.Address{{Name: "Elemta Webmail", Address: "webmail@localhost"}})
	title := obj.Title
	if title == "" {
		title = obj.ID
	}
	h.SetSubject(title)
	h.Set(objectHeader, obj.ID)
	ct := obj.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Transfer-Encoding", "base64")
	var buf bytes.Buffer
	w, err := message.CreateWriter(&buf, h.Header)
	if err != nil {
		return nil, fmt.Errorf("webmail: encode object: %w", err)
	}
	if _, err := w.Write(obj.Data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var errNotObject = errors.New("webmail: not a stored object")

func decodeObject(raw []byte) (Object, error) {
	e, err := message.Read(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return Object{}, err
	}
	id := strings.TrimSpace(e.Header.Get(objectHeader))
	if id == "" {
		return Object{}, errNotObject
	}
	mh := mail.Header{Header: e.Header}
	title, _ := mh.Subject()
	date, _ := mh.Date()
	ct, _, _ := e.Header.ContentType()
	data, err := io.ReadAll(io.LimitReader(e.Body, 16<<20))
	if err != nil {
		return Object{}, err
	}
	return Object{ID: id, Title: title, ContentType: ct, Data: data, Modified: date}, nil
}
