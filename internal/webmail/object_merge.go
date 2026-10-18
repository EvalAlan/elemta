package webmail

// Contacts and tasks get the same care as events (see calendar_store.go):
// the webmail edits a model of the fields it shows, so a rewrite from the
// model alone would drop what phones and desktop clients store beside them
// (photos, structured addresses, alarms, repeating tasks, due times). When
// a field the webmail shows is unchanged, the stored form of it is kept
// too, since the model is a simplification (one address line, a due day).

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
)

// mergeCard renders c over the stored card old (nil for a new contact).
func mergeCard(old vcard.Card, c Contact) vcard.Card {
	card := contactToCard(c)
	if old == nil {
		return card
	}
	was := cardToContact(old)
	was.ID = c.ID
	keepIfSame := func(same bool, fields ...string) {
		if !same {
			return
		}
		for _, f := range fields {
			if v, ok := old[f]; ok {
				card[f] = v
			}
		}
	}
	keepIfSame(was.Name == c.Name, vcard.FieldFormattedName, vcard.FieldName)
	keepIfSame(reflect.DeepEqual(was.Emails, c.Emails), vcard.FieldEmail)
	keepIfSame(reflect.DeepEqual(was.Phones, c.Phones), vcard.FieldTelephone)
	keepIfSame(was.Org == c.Org, vcard.FieldOrganization)
	keepIfSame(was.Title == c.Title, vcard.FieldTitle)
	keepIfSame(was.Address == c.Address, vcard.FieldAddress)
	keepIfSame(was.Birthday == c.Birthday, vcard.FieldBirthday)
	keepIfSame(was.Website == c.Website, vcard.FieldURL)
	keepIfSame(was.Notes == c.Notes, vcard.FieldNote)
	keepIfSame(reflect.DeepEqual(was.Groups, c.Groups), vcard.FieldCategories)
	managed := map[string]bool{
		vcard.FieldVersion: true, vcard.FieldUID: true, vcard.FieldFormattedName: true, vcard.FieldName: true,
		vcard.FieldEmail: true, vcard.FieldTelephone: true, vcard.FieldOrganization: true, vcard.FieldTitle: true,
		vcard.FieldAddress: true, vcard.FieldBirthday: true, vcard.FieldURL: true, vcard.FieldNote: true,
		vcard.FieldCategories: true,
	}
	for f, v := range old {
		if !managed[f] {
			card[f] = v
		}
	}
	// A 3.0 card stays 3.0, which is what the client that wrote it reads.
	if v, ok := old[vcard.FieldVersion]; ok {
		card[vcard.FieldVersion] = v
	}
	return card
}

func (s *Server) putContact(ctx context.Context, sess *Session, c Contact) error {
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollContacts)
		if err != nil {
			return err
		}
		var old vcard.Card
		for _, o := range objs {
			if o.ID == objectID(c.ID) {
				old, _ = vcard.NewDecoder(bytes.NewReader(o.Data)).Decode()
				break
			}
		}
		data, err := encodeCard(mergeCard(old, c))
		if err != nil {
			return err
		}
		return st.PutObject(ctx, CollContacts, Object{ID: c.ID, Title: c.Display(), ContentType: "text/vcard", Data: data})
	})
}

// managedTaskProps are the VTODO properties Task.toComponent writes.
var managedTaskProps = map[string]bool{
	ical.PropUID: true, ical.PropDateTimeStamp: true, ical.PropCreated: true, ical.PropSummary: true,
	ical.PropDescription: true, ical.PropDue: true, ical.PropPriority: true, ical.PropStatus: true,
	ical.PropPercentComplete: true, ical.PropCompleted: true, "X-ELEMTA-LIST": true,
}

// mergeTask renders t into the stored calendar old (nil for a new task),
// keeping its other components and the task's unmanaged properties.
func mergeTask(old *ical.Calendar, t Task, loc *time.Location, now time.Time) ([]byte, error) {
	comp := t.toComponent(now)
	if old == nil {
		return encodeCalendar("", now, comp)
	}
	replaced := false
	for i, c := range old.Children {
		if c.Name != ical.CompToDo {
			continue
		}
		if p := c.Props.Get(ical.PropUID); p == nil || p.Value != t.UID {
			continue
		}
		if was, ok := taskFromComponent(c, loc); ok && was.Due.Equal(t.Due) {
			// The webmail shows a due day; a client's due time stays.
			if due := c.Props[ical.PropDue]; len(due) > 0 {
				comp.Props[ical.PropDue] = due
			}
		}
		for name, props := range c.Props {
			if !managedTaskProps[name] {
				comp.Props[name] = props
			}
		}
		comp.Children = c.Children
		old.Children[i] = comp
		replaced = true
		break
	}
	if !replaced {
		old.Children = append(old.Children, comp)
	}
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(old); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) putTask(ctx context.Context, sess *Session, t Task) error {
	loc := s.loc(sess)
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollTasks)
		if err != nil {
			return err
		}
		var old *ical.Calendar
		id := t.UID
		for _, o := range objs {
			cal, err := ical.NewDecoder(bytes.NewReader(o.Data)).Decode()
			if err != nil {
				continue
			}
			for _, c := range cal.Children {
				if p := c.Props.Get(ical.PropUID); c.Name == ical.CompToDo && p != nil && p.Value == t.UID {
					old, id = cal, o.ID
				}
			}
			if old != nil {
				break
			}
		}
		data, err := mergeTask(old, t, loc, s.now())
		if err != nil {
			return err
		}
		return st.PutObject(ctx, CollTasks, Object{ID: id, Title: t.Summary, ContentType: "text/calendar", Data: data})
	})
}
