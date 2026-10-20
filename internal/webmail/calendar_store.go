package webmail

// Writing events back without losing what other clients stored.
//
// The webmail edits an Event, a model of the fields it shows. Objects that
// came from CalDAV clients or imports carry more: several alarms, VTIMEZONE
// definitions, vendor properties, attachments, and overrides of single
// occurrences (VEVENTs with a RECURRENCE-ID) which decodeCalendar shows as
// separate events named "<uid>-<recurrence id>". Rewriting the object from
// the Event alone would drop all of that, and editing one of those
// overrides would create a second, standalone event beside it.
//
// putEvent and deleteEvent therefore merge into the stored object: the
// fields the webmail manages are replaced, everything else is kept.

import (
	"bytes"
	"context"
	"time"

	"github.com/emersion/go-ical"
)

// managedEventProps are the VEVENT properties toComponent writes. Anything
// else on a stored event is carried over when the webmail rewrites it.
// DURATION is listed because toComponent always writes DTEND, and an event
// may not have both.
var managedEventProps = map[string]bool{
	ical.PropUID: true, ical.PropDateTimeStamp: true, ical.PropLastModified: true,
	ical.PropDateTimeStart: true, ical.PropDateTimeEnd: true, ical.PropDuration: true,
	ical.PropSummary: true, ical.PropLocation: true, ical.PropDescription: true,
	ical.PropURL: true, ical.PropStatus: true, ical.PropTransparency: true,
	ical.PropSequence: true, "X-ELEMTA-CALENDAR": true, ical.PropRecurrenceRule: true,
	ical.PropExceptionDates: true, ical.PropOrganizer: true, ical.PropAttendee: true,
	ical.PropRecurrenceID: true,
}

// overrideUID is the name decodeCalendar gives an override of one
// occurrence.
func overrideUID(uid string, rid time.Time) string {
	return uid + "-" + rid.UTC().Format("20060102T150405Z")
}

// recurrenceID reads an override's RECURRENCE-ID, or reports false for a
// series or single event.
func recurrenceID(comp *ical.Component) (time.Time, bool) {
	rid := comp.Props.Get(ical.PropRecurrenceID)
	if rid == nil {
		return time.Time{}, false
	}
	loc := time.UTC
	if start, _, err := propTime(comp.Props.Get(ical.PropDateTimeStart), time.UTC); err == nil {
		loc = start.Location()
	}
	t, _, err := propTime(rid, loc)
	return t, err == nil
}

// storedEvent finds the stored object an event lives in: its own, or for
// an override the series' object. comp is the event's component in cal.
type storedEvent struct {
	obj  Object
	cal  *ical.Calendar
	comp *ical.Component
}

func findStoredEvent(objs []Object, uid string) *storedEvent {
	id := objectID(uid)
	// A series is normally in the object named after its UID, but an
	// imported or synced object may be named otherwise; that is used when
	// no object of the expected name has it.
	var elsewhere *storedEvent
	for _, o := range objs {
		cal, err := ical.NewDecoder(bytes.NewReader(o.Data)).Decode()
		if err != nil {
			continue
		}
		for _, child := range cal.Children {
			if child.Name != ical.CompEvent {
				continue
			}
			cuid := ""
			if p := child.Props.Get(ical.PropUID); p != nil {
				cuid = p.Value
			}
			rid, isOverride := recurrenceID(child)
			switch {
			case !isOverride && cuid == uid && o.ID == id:
				return &storedEvent{obj: o, cal: cal, comp: child}
			case !isOverride && cuid == uid && elsewhere == nil:
				elsewhere = &storedEvent{obj: o, cal: cal, comp: child}
			case isOverride && overrideUID(cuid, rid) == uid:
				return &storedEvent{obj: o, cal: cal, comp: child}
			}
		}
	}
	return elsewhere
}

// carryProps copies onto dst the properties of src that the webmail
// doesn't manage.
func carryProps(dst, src *ical.Component) {
	for name, props := range src.Props {
		if managedEventProps[name] {
			continue
		}
		if _, set := dst.Props[name]; set {
			continue
		}
		dst.Props[name] = append([]ical.Prop(nil), props...)
	}
}

// keepAlarms keeps the stored alarms when the reminder the webmail shows
// for them is unchanged, so a phone's second alarm or email alarm survives
// an unrelated edit.
func keepAlarms(dst, src *ical.Component, reminder int) {
	old, err := eventFromComponent(src, time.UTC)
	if err != nil || old.Reminder != reminder {
		return
	}
	var children []*ical.Component
	for _, c := range dst.Children {
		if c.Name != ical.CompAlarm {
			children = append(children, c)
		}
	}
	for _, c := range src.Children {
		if c.Name == ical.CompAlarm {
			children = append(children, c)
		}
	}
	dst.Children = children
}

func (s *Server) putEvent(ctx context.Context, sess *Session, e Event) error {
	now := s.now()
	e.Modified = now.UTC()
	err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollCalendar)
		if err != nil {
			return err
		}
		data, id, err := mergeEvent(findStoredEvent(objs, e.UID), e, now)
		if err != nil {
			return err
		}
		return st.PutObject(ctx, CollCalendar, Object{ID: id, Title: e.Summary, ContentType: "text/calendar", Data: data})
	})
	if err == nil {
		s.calendarChanged(sess)
	}
	return err
}

// mergeEvent renders e into the object it is stored in (or a new one when
// stored is nil), and returns the data and the object ID to write.
func mergeEvent(stored *storedEvent, e Event, now time.Time) ([]byte, string, error) {
	if stored == nil {
		data, err := encodeCalendar("", now, e.toComponent(now))
		return data, e.UID, err
	}
	if _, isOverride := recurrenceID(stored.comp); isOverride {
		// An override stays an override of its series: same UID, same
		// RECURRENCE-ID, no rule of its own.
		e.UID = stored.comp.Props.Get(ical.PropUID).Value
		e.RRule, e.ExDates = "", nil
		comp := e.toComponent(now)
		comp.Props[ical.PropRecurrenceID] = append([]ical.Prop(nil), stored.comp.Props[ical.PropRecurrenceID]...)
		carryProps(comp, stored.comp)
		keepAlarms(comp, stored.comp, e.Reminder)
		return replaceComponent(stored, comp, nil)
	}
	// A series keeps its overrides while its rule is unchanged. decodeCalendar
	// added an EXDATE for each so the series doesn't show them twice; those
	// are dropped here, since the override itself replaces the occurrence.
	old, _ := eventFromComponent(stored.comp, time.UTC)
	var keep []*ical.Component
	var rids []time.Time
	if old.RRule == e.RRule {
		for _, c := range stored.cal.Children {
			if c.Name != ical.CompEvent || c == stored.comp {
				continue
			}
			if p := c.Props.Get(ical.PropUID); p == nil || p.Value != e.UID {
				continue
			}
			if rid, ok := recurrenceID(c); ok {
				keep = append(keep, c)
				rids = append(rids, rid)
			}
		}
	}
	var exdates []time.Time
	for _, x := range e.ExDates {
		synthetic := false
		for _, r := range rids {
			if x.Equal(r) {
				synthetic = true
				break
			}
		}
		if !synthetic {
			exdates = append(exdates, x)
		}
	}
	e.ExDates = exdates
	comp := e.toComponent(now)
	carryProps(comp, stored.comp)
	keepAlarms(comp, stored.comp, e.Reminder)
	return replaceComponent(stored, comp, keep)
}

// replaceComponent writes the stored calendar back with comp in place of
// the stored component. For a series, overrides is the list of its
// overrides to keep; others of the series are dropped. Other components
// (VTIMEZONE and anything unknown) are kept.
func replaceComponent(stored *storedEvent, comp *ical.Component, overrides []*ical.Component) ([]byte, string, error) {
	_, isOverride := recurrenceID(stored.comp)
	uid := ""
	if p := stored.comp.Props.Get(ical.PropUID); p != nil {
		uid = p.Value
	}
	var children []*ical.Component
	for _, c := range stored.cal.Children {
		switch {
		case c == stored.comp:
			children = append(children, comp)
		case !isOverride && c.Name == ical.CompEvent && c.Props.Get(ical.PropUID) != nil && c.Props.Get(ical.PropUID).Value == uid:
			// The series' overrides: only those still valid are kept below.
		default:
			children = append(children, c)
		}
	}
	children = append(children, overrides...)
	stored.cal.Children = children
	stored.cal.Props.Del(ical.PropMethod) // a stored object is not an iTIP message
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(stored.cal); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), stored.obj.ID, nil
}

func (s *Server) deleteEvent(ctx context.Context, sess *Session, uid string) error {
	err := s.deleteEventIn(ctx, sess, uid)
	if err == nil {
		s.calendarChanged(sess)
	}
	return err
}

func (s *Server) deleteEventIn(ctx context.Context, sess *Session, uid string) error {
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollCalendar)
		if err != nil {
			return err
		}
		stored := findStoredEvent(objs, uid)
		if stored == nil {
			return st.DeleteObject(ctx, CollCalendar, uid)
		}
		if _, isOverride := recurrenceID(stored.comp); !isOverride {
			return st.DeleteObject(ctx, CollCalendar, stored.obj.ID)
		}
		data, err := deleteOverride(stored)
		if err != nil {
			return err
		}
		return st.PutObject(ctx, CollCalendar, Object{ID: stored.obj.ID, ContentType: "text/calendar", Data: data})
	})
}

// deleteOverride removes one override from its series' object. Deleting an
// override deletes that occurrence, so the series gets an EXDATE for it.
func deleteOverride(stored *storedEvent) ([]byte, error) {
	ridProp := stored.comp.Props.Get(ical.PropRecurrenceID)
	uid := stored.comp.Props.Get(ical.PropUID).Value
	var children []*ical.Component
	for _, c := range stored.cal.Children {
		if c == stored.comp {
			continue
		}
		if c.Name == ical.CompEvent && c.Props.Get(ical.PropRecurrenceID) == nil && c.Props.Get(ical.PropUID) != nil && c.Props.Get(ical.PropUID).Value == uid {
			ex := *ridProp
			ex.Name = ical.PropExceptionDates
			c.Props.Add(&ex)
		}
		children = append(children, c)
	}
	stored.cal.Children = children
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(stored.cal); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
