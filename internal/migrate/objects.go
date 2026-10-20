package migrate

// Calendars, tasks and contacts, from the iCalendar (.ics) and vCard (.vcf)
// files every calendar and address book can export. Each event, task or
// contact becomes one object in the user's Calendar, Tasks or Contacts
// folder, in the format the webmail keeps them in (webmail.ObjectMessage),
// so the webmail and CalDAV/CardDAV clients see them at once. The import
// key is the object's UID and its content, so running an import again
// stores nothing new, while an export taken later with changes adds the
// newer version, which the webmail prefers.
//
// These go through the IMAP object store. A webmail configured with
// object_store = "postgres" keeps objects elsewhere and needs its own
// import (the user's CalDAV/CardDAV account takes the same files).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/webmail"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
)

// Object is one calendar entry or contact, ready to import.
type Object struct {
	Folder string // Calendar, Tasks or Contacts
	ID     string
	Title  string
	Type   string // content type
	Data   []byte
}

// SplitCalendar turns an iCalendar file into one object per event or task,
// keeping a recurring event's exceptions (same UID) together and giving
// each object the time zones the file defines.
func SplitCalendar(r io.Reader) ([]Object, error) {
	cal, err := ical.NewDecoder(r).Decode()
	if err != nil {
		return nil, fmt.Errorf("read calendar: %w", err)
	}
	var zones []*ical.Component
	type group struct {
		folder string
		comps  []*ical.Component
	}
	groups := map[string]*group{}
	var order []string
	for _, c := range cal.Children {
		switch c.Name {
		case ical.CompTimezone:
			zones = append(zones, c)
		case ical.CompEvent, ical.CompToDo:
			uid := ""
			if p := c.Props.Get(ical.PropUID); p != nil {
				uid = strings.TrimSpace(p.Value)
			}
			if uid == "" {
				// An entry without a UID still gets a stable one, from
				// its content, so a rerun recognises it.
				var buf bytes.Buffer
				_ = ical.NewEncoder(&buf).Encode(&ical.Calendar{Component: &ical.Component{Name: ical.CompCalendar, Props: ical.Props{}, Children: []*ical.Component{c}}})
				sum := sha256.Sum256(buf.Bytes())
				uid = "import-" + hex.EncodeToString(sum[:12])
				p := ical.NewProp(ical.PropUID)
				p.Value = uid
				c.Props.Set(p)
			}
			folder := string(webmail.CollCalendar)
			if c.Name == ical.CompToDo {
				folder = string(webmail.CollTasks)
			}
			key := folder + "\x00" + uid
			if groups[key] == nil {
				groups[key] = &group{folder: folder}
				order = append(order, key)
			}
			groups[key].comps = append(groups[key].comps, c)
		}
	}
	out := make([]Object, 0, len(order))
	for _, key := range order {
		g := groups[key]
		obj := ical.NewCalendar()
		obj.Props.SetText(ical.PropVersion, "2.0")
		obj.Props.SetText(ical.PropProductID, "-//Elemta//Migration//EN")
		obj.Children = append(append([]*ical.Component(nil), zones...), g.comps...)
		var buf bytes.Buffer
		if err := ical.NewEncoder(&buf).Encode(obj); err != nil {
			return nil, fmt.Errorf("encode %s: %w", key, err)
		}
		title := ""
		if p := g.comps[0].Props.Get(ical.PropSummary); p != nil {
			title = p.Value
		}
		uid := strings.SplitN(key, "\x00", 2)[1]
		out = append(out, Object{Folder: g.folder, ID: uid, Title: title, Type: "text/calendar; charset=utf-8", Data: buf.Bytes()})
	}
	return out, nil
}

// SplitContacts turns a vCard file into one object per contact.
func SplitContacts(r io.Reader) ([]Object, error) {
	dec := vcard.NewDecoder(r)
	var out []Object
	for {
		card, err := dec.Decode()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("read contacts: %w", err)
		}
		var buf bytes.Buffer
		uid := strings.TrimSpace(card.Value(vcard.FieldUID))
		if uid == "" {
			_ = vcard.NewEncoder(&buf).Encode(card)
			sum := sha256.Sum256(buf.Bytes())
			uid = "import-" + hex.EncodeToString(sum[:12])
			card.SetValue(vcard.FieldUID, uid)
			buf.Reset()
		}
		if card.Value(vcard.FieldVersion) == "" {
			card.SetValue(vcard.FieldVersion, "3.0")
		}
		if err := vcard.NewEncoder(&buf).Encode(card); err != nil {
			return out, fmt.Errorf("encode contact %s: %w", uid, err)
		}
		out = append(out, Object{Folder: string(webmail.CollContacts), ID: uid, Title: card.PreferredValue(vcard.FieldFormattedName), Type: "text/vcard; charset=utf-8", Data: buf.Bytes()})
	}
}

// ObjectReport counts an object import.
type ObjectReport struct {
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
	Failed   int `json:"failed"`
}

// ImportObjects stores objects in dest's folders.
func ImportObjects(ctx context.Context, dest string, objs []Object, to Importer) (ObjectReport, error) {
	var rep ObjectReport
	for _, o := range objs {
		raw, err := webmail.ObjectMessage(o.ID, o.Title, o.Type, o.Data)
		if err != nil {
			rep.Failed++
			continue
		}
		sum := sha256.Sum256(o.Data)
		key := "object:" + o.Folder + ":" + o.ID + ":" + hex.EncodeToString(sum[:16])
		res, err := to.Import(ctx, mailpolicy.Import{Address: dest, Folder: o.Folder, Flags: []string{`\Seen`}, Key: key, Raw: raw})
		switch {
		case err == nil && res.Duplicate:
			rep.Skipped++
		case err == nil:
			rep.Imported++
		case errors.Is(err, mailpolicy.ErrQuota):
			return rep, fmt.Errorf("%s is over its quota; raise it and run again", dest)
		default:
			var apiErr *mailpolicy.APIError
			if errors.As(err, &apiErr) && apiErr.Status < 500 {
				rep.Failed++
				continue
			}
			return rep, err
		}
	}
	return rep, nil
}
