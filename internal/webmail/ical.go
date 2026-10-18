package webmail

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

// Event is one calendar event, stored as an iCalendar VEVENT so it can be
// exported to, and imported from, any other calendar unchanged.
type Event struct {
	UID         string
	Summary     string
	Location    string
	Description string
	// Start and End bound the event; End is exclusive. All-day events
	// start at midnight of their first day and end at midnight after
	// their last, in the zone they are shown in.
	Start, End time.Time
	AllDay     bool
	// RRule is the recurrence rule without the "RRULE:" prefix, empty for
	// a single event. ExDates are occurrences removed from it.
	RRule   string
	ExDates []time.Time
	// Calendar names the calendar the event belongs to (Personal, Work…).
	Calendar  string
	Organizer *Attendee
	Attendees []Attendee
	Sequence  int
	Status    string // CONFIRMED, TENTATIVE or CANCELLED
	// Busy is false for events marked free (TRANSP:TRANSPARENT).
	Busy bool
	// Reminder is minutes before the start to remind, or -1 for none.
	Reminder int
	Modified time.Time
	// URL is a link for the event, such as a video meeting.
	URL string
	// ReadOnly marks events made from other data (contact birthdays),
	// which the calendar shows but can't edit.
	ReadOnly bool
}

// Attendee is a participant in a meeting.
type Attendee struct {
	Email  string
	Name   string
	Status string // NEEDS-ACTION, ACCEPTED, DECLINED, TENTATIVE
	// Optional marks an attendee whose presence isn't required.
	Optional bool
}

// Label is the attendee's name, or their address.
func (a Attendee) Label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.Email
}

// StatusLabel is the participation status in words.
func (a Attendee) StatusLabel() string {
	switch a.Status {
	case "ACCEPTED":
		return "Going"
	case "DECLINED":
		return "Not going"
	case "TENTATIVE":
		return "Maybe"
	}
	return "Not replied"
}

// StatusClass is the CSS class for the status.
func (a Attendee) StatusClass() string {
	switch a.Status {
	case "ACCEPTED":
		return "rsvp-accepted"
	case "DECLINED":
		return "rsvp-declined"
	case "TENTATIVE":
		return "rsvp-tentative"
	}
	return "rsvp-pending"
}

// Duration is the event's length.
func (e Event) Duration() time.Duration { return e.End.Sub(e.Start) }

// Recurring reports whether the event repeats.
func (e Event) Recurring() bool { return e.RRule != "" }

// HasAttendees reports whether the event is a meeting with other people.
func (e Event) HasAttendees() bool { return len(e.Attendees) > 0 }

// IsOrganizer reports whether addr organises the event. An event with no
// organizer is the user's own.
func (e Event) IsOrganizer(addr string) bool {
	return e.Organizer == nil || strings.EqualFold(e.Organizer.Email, addr)
}

const prodID = "-//Elemta//Webmail//EN"

// errNoEvent is returned when an iCalendar object holds no event.
var errNoEvent = errors.New("webmail: no event in calendar data")

// mailtoAddr strips the mailto: scheme from a calendar address.
func mailtoAddr(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 7 && strings.EqualFold(v[:7], "mailto:") {
		v = v[7:]
	}
	return v
}

// windowsZones maps the time zone names Outlook and Exchange put in TZID to
// IANA names. It covers the zones people actually send invitations from;
// anything else falls back to the user's own zone.
var windowsZones = map[string]string{
	"Eastern Standard Time": "America/New_York", "Central Standard Time": "America/Chicago",
	"Mountain Standard Time": "America/Denver", "US Mountain Standard Time": "America/Phoenix",
	"Pacific Standard Time": "America/Los_Angeles", "Alaskan Standard Time": "America/Anchorage",
	"Hawaiian Standard Time": "Pacific/Honolulu", "Atlantic Standard Time": "America/Halifax",
	"GMT Standard Time": "Europe/London", "Greenwich Standard Time": "Atlantic/Reykjavik",
	"W. Europe Standard Time": "Europe/Berlin", "Romance Standard Time": "Europe/Paris",
	"Central Europe Standard Time": "Europe/Budapest", "Central European Standard Time": "Europe/Warsaw",
	"E. Europe Standard Time": "Europe/Chisinau", "FLE Standard Time": "Europe/Kiev",
	"GTB Standard Time": "Europe/Bucharest", "Russian Standard Time": "Europe/Moscow",
	"Israel Standard Time": "Asia/Jerusalem", "South Africa Standard Time": "Africa/Johannesburg",
	"Arabian Standard Time": "Asia/Dubai", "India Standard Time": "Asia/Kolkata",
	"China Standard Time": "Asia/Shanghai", "Singapore Standard Time": "Asia/Singapore",
	"Tokyo Standard Time": "Asia/Tokyo", "Korea Standard Time": "Asia/Seoul",
	"AUS Eastern Standard Time": "Australia/Sydney", "W. Australia Standard Time": "Australia/Perth",
	"New Zealand Standard Time": "Pacific/Auckland", "E. South America Standard Time": "America/Sao_Paulo",
	"UTC": "UTC", "Coordinated Universal Time": "UTC",
}

// propTime parses a DTSTART-like property. It accepts what real calendars
// send: UTC, floating, IANA and Windows TZIDs, and bare dates. A TZID that
// can't be resolved is read in fallback, which beats rejecting the event.
func propTime(p *ical.Prop, fallback *time.Location) (t time.Time, dateOnly bool, err error) {
	if p == nil {
		return time.Time{}, false, errors.New("missing")
	}
	v := strings.TrimSpace(p.Value)
	if p.ValueType() == ical.ValueDate || len(v) == 8 {
		t, err := time.ParseInLocation("20060102", v, fallback)
		return t, true, err
	}
	if strings.HasSuffix(v, "Z") {
		t, err := time.ParseInLocation("20060102T150405Z", v, time.UTC)
		return t, false, err
	}
	loc := fallback
	if tzid := strings.Trim(p.Params.Get(ical.PropTimezoneID), `"`); tzid != "" {
		if l, err := time.LoadLocation(tzid); err == nil {
			loc = l
		} else if iana, ok := windowsZones[tzid]; ok {
			if l, err := time.LoadLocation(iana); err == nil {
				loc = l
			}
		} else {
			// Some exporters prefix the IANA name with their own path
			// (/mozilla.org/20050126_1/Europe/Paris); try its tail.
			parts := strings.Split(tzid, "/")
			for n := 3; n >= 2; n-- {
				if len(parts) >= n {
					if l, err := time.LoadLocation(strings.Join(parts[len(parts)-n:], "/")); err == nil {
						loc = l
						break
					}
				}
			}
		}
	}
	t, err = time.ParseInLocation("20060102T150405", v, loc)
	return t, false, err
}

// eventFromComponent reads a VEVENT. loc is the zone floating times and
// all-day dates are read in: the user's own.
func eventFromComponent(comp *ical.Component, loc *time.Location) (Event, error) {
	e := Event{Busy: true, Reminder: -1, Status: "CONFIRMED"}
	props := comp.Props
	text := func(name string) string {
		if p := props.Get(name); p != nil {
			s, err := p.Text()
			if err == nil {
				return s
			}
			return p.Value
		}
		return ""
	}
	e.UID = text(ical.PropUID)
	e.Summary = text(ical.PropSummary)
	e.Location = text(ical.PropLocation)
	e.Description = text(ical.PropDescription)
	e.URL = text(ical.PropURL)
	if s := strings.ToUpper(text(ical.PropStatus)); s != "" {
		e.Status = s
	}
	if strings.EqualFold(text(ical.PropTransparency), "TRANSPARENT") {
		e.Busy = false
	}
	if p := props.Get(ical.PropSequence); p != nil {
		e.Sequence, _ = strconv.Atoi(strings.TrimSpace(p.Value))
	}
	if cats := props.Get(ical.PropCategories); cats != nil {
		if l, err := cats.TextList(); err == nil && len(l) > 0 {
			e.Calendar = l[0]
		}
	}
	if c := text("X-ELEMTA-CALENDAR"); c != "" {
		e.Calendar = c
	}
	var dateOnly bool
	var err error
	e.Start, dateOnly, err = propTime(props.Get(ical.PropDateTimeStart), loc)
	if err != nil {
		return e, fmt.Errorf("webmail: event %q: start: %w", e.UID, err)
	}
	e.AllDay = dateOnly
	switch {
	case props.Get(ical.PropDateTimeEnd) != nil:
		e.End, _, err = propTime(props.Get(ical.PropDateTimeEnd), loc)
		if err != nil {
			return e, fmt.Errorf("webmail: event %q: end: %w", e.UID, err)
		}
	case props.Get(ical.PropDuration) != nil:
		d, err := props.Get(ical.PropDuration).Duration()
		if err != nil {
			return e, fmt.Errorf("webmail: event %q: duration: %w", e.UID, err)
		}
		e.End = e.Start.Add(d)
	case e.AllDay:
		e.End = e.Start.AddDate(0, 0, 1)
	default:
		e.End = e.Start
	}
	if !e.End.After(e.Start) && e.AllDay {
		e.End = e.Start.AddDate(0, 0, 1)
	}
	if e.End.Before(e.Start) {
		e.End = e.Start
	}
	if p := props.Get(ical.PropRecurrenceRule); p != nil {
		e.RRule = strings.TrimSpace(p.Value)
	}
	for _, p := range props.Values(ical.PropExceptionDates) {
		for _, v := range strings.Split(p.Value, ",") {
			q := p
			q.Value = v
			if t, _, err := propTime(&q, e.Start.Location()); err == nil {
				e.ExDates = append(e.ExDates, t)
			}
		}
	}
	if p := props.Get(ical.PropOrganizer); p != nil {
		e.Organizer = &Attendee{Email: mailtoAddr(p.Value), Name: p.Params.Get(ical.ParamCommonName)}
	}
	for _, p := range props.Values(ical.PropAttendee) {
		a := Attendee{
			Email: mailtoAddr(p.Value), Name: p.Params.Get(ical.ParamCommonName),
			Status:   strings.ToUpper(p.Params.Get(ical.ParamParticipationStatus)),
			Optional: strings.EqualFold(p.Params.Get(ical.ParamRole), "OPT-PARTICIPANT"),
		}
		if a.Status == "" {
			a.Status = "NEEDS-ACTION"
		}
		if a.Email != "" {
			e.Attendees = append(e.Attendees, a)
		}
	}
	for _, child := range comp.Children {
		if child.Name != ical.CompAlarm {
			continue
		}
		if tr := child.Props.Get(ical.PropTrigger); tr != nil {
			if d, err := tr.Duration(); err == nil && d <= 0 {
				e.Reminder = int(-d / time.Minute)
				break
			}
		}
	}
	if p := props.Get(ical.PropLastModified); p != nil {
		e.Modified, _, _ = propTime(p, time.UTC)
	}
	if e.UID == "" {
		return e, errors.New("webmail: event without a UID")
	}
	return e, nil
}

// toComponent writes the event as a VEVENT. Timed events keep their zone
// (TZID), so a weekly 9:00 meeting stays at 9:00 across daylight saving.
func (e Event) toComponent(now time.Time) *ical.Component {
	ev := ical.NewEvent()
	p := ev.Props
	p.SetText(ical.PropUID, e.UID)
	p.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	if !e.Modified.IsZero() {
		p.SetDateTime(ical.PropLastModified, e.Modified.UTC())
	}
	if e.AllDay {
		p.SetDate(ical.PropDateTimeStart, e.Start)
		p.SetDate(ical.PropDateTimeEnd, e.End)
	} else {
		p.SetDateTime(ical.PropDateTimeStart, e.Start)
		p.SetDateTime(ical.PropDateTimeEnd, e.End)
	}
	p.SetText(ical.PropSummary, e.Summary)
	if e.Location != "" {
		p.SetText(ical.PropLocation, e.Location)
	}
	if e.Description != "" {
		p.SetText(ical.PropDescription, e.Description)
	}
	if e.URL != "" {
		p.SetText(ical.PropURL, e.URL)
	}
	if e.Status != "" {
		p.SetText(ical.PropStatus, e.Status)
	}
	if !e.Busy {
		p.SetText(ical.PropTransparency, "TRANSPARENT")
	}
	if e.Sequence > 0 {
		p.SetText(ical.PropSequence, strconv.Itoa(e.Sequence))
	}
	if e.Calendar != "" {
		p.SetText("X-ELEMTA-CALENDAR", e.Calendar)
	}
	if e.RRule != "" {
		rp := ical.NewProp(ical.PropRecurrenceRule)
		rp.SetValueType(ical.ValueRecurrence)
		rp.Value = e.RRule
		p.Set(rp)
	}
	for _, x := range e.ExDates {
		xp := ical.NewProp(ical.PropExceptionDates)
		if e.AllDay {
			xp.SetDate(x)
		} else {
			xp.SetDateTime(x.In(e.Start.Location()))
		}
		p.Add(xp)
	}
	if e.Organizer != nil {
		op := ical.NewProp(ical.PropOrganizer)
		op.Value = "mailto:" + e.Organizer.Email
		if e.Organizer.Name != "" {
			op.Params.Set(ical.ParamCommonName, e.Organizer.Name)
		}
		p.Set(op)
	}
	for _, a := range e.Attendees {
		ap := ical.NewProp(ical.PropAttendee)
		ap.Value = "mailto:" + a.Email
		if a.Name != "" {
			ap.Params.Set(ical.ParamCommonName, a.Name)
		}
		role := "REQ-PARTICIPANT"
		if a.Optional {
			role = "OPT-PARTICIPANT"
		}
		ap.Params.Set(ical.ParamRole, role)
		status := a.Status
		if status == "" {
			status = "NEEDS-ACTION"
		}
		ap.Params.Set(ical.ParamParticipationStatus, status)
		if status == "NEEDS-ACTION" {
			ap.Params.Set(ical.ParamRSVP, "TRUE")
		}
		p.Add(ap)
	}
	if e.Reminder >= 0 {
		alarm := ical.NewComponent(ical.CompAlarm)
		alarm.Props.SetText(ical.PropAction, "DISPLAY")
		alarm.Props.SetText(ical.PropDescription, e.Summary)
		tr := ical.NewProp(ical.PropTrigger)
		tr.SetDuration(-time.Duration(e.Reminder) * time.Minute)
		alarm.Props.Set(tr)
		ev.Children = append(ev.Children, alarm)
	}
	return ev.Component
}

// encodeCalendar renders events as one VCALENDAR, with an iTIP method for
// invitations (REQUEST, REPLY, CANCEL) or none for storage and export.
func encodeCalendar(method string, now time.Time, comps ...*ical.Component) ([]byte, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, prodID)
	if method != "" {
		cal.Props.SetText(ical.PropMethod, method)
	}
	cal.Children = append(cal.Children, comps...)
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("webmail: encode calendar: %w", err)
	}
	return buf.Bytes(), nil
}

// parsedCalendar is what decodeCalendar found: the iTIP method and the
// events, with recurrence overrides (RECURRENCE-ID) folded away.
type parsedCalendar struct {
	Method string
	Events []Event
}

// decodeCalendar reads every VEVENT in data. Overrides of single
// occurrences of a recurring event become separate events, and the series
// gets an EXDATE for each, which is how this calendar models "edit this
// occurrence".
func decodeCalendar(data []byte, loc *time.Location) (parsedCalendar, error) {
	var out parsedCalendar
	dec := ical.NewDecoder(bytes.NewReader(data))
	cal, err := dec.Decode()
	if err != nil {
		return out, fmt.Errorf("webmail: read calendar: %w", err)
	}
	if m := cal.Props.Get(ical.PropMethod); m != nil {
		out.Method = strings.ToUpper(strings.TrimSpace(m.Value))
	}
	series := map[string]int{}
	var overrides []Event
	for _, child := range cal.Children {
		if child.Name != ical.CompEvent {
			continue
		}
		e, err := eventFromComponent(child, loc)
		if err != nil {
			continue
		}
		if rid := child.Props.Get(ical.PropRecurrenceID); rid != nil {
			t, _, err := propTime(rid, e.Start.Location())
			if err == nil {
				// The override needs its own identity in storage.
				e.ExDates = []time.Time{t}
				overrides = append(overrides, e)
				continue
			}
		}
		series[e.UID] = len(out.Events)
		out.Events = append(out.Events, e)
	}
	for _, o := range overrides {
		rid := o.ExDates[0]
		if i, ok := series[o.UID]; ok {
			out.Events[i].ExDates = append(out.Events[i].ExDates, rid)
		}
		o.ExDates = nil
		o.UID = o.UID + "-" + rid.UTC().Format("20060102T150405Z")
		o.RRule = ""
		out.Events = append(out.Events, o)
	}
	if len(out.Events) == 0 {
		return out, errNoEvent
	}
	return out, nil
}

// Occurrence is one instance of an event in a date range.
type Occurrence struct {
	Event      *Event
	Start, End time.Time
}

// maxOccurrences bounds the expansion of one rule within one view, so a
// FREQ=MINUTELY import can't make a page enormous.
const maxOccurrences = 500

// occurrences returns the instances of e that overlap [from, to).
func (e *Event) occurrences(from, to time.Time) []Occurrence {
	dur := e.Duration()
	if e.RRule == "" {
		if e.Start.Before(to) && (e.End.After(from) || (dur == 0 && !e.Start.Before(from))) {
			return []Occurrence{{Event: e, Start: e.Start, End: e.End}}
		}
		return nil
	}
	opt, err := rrule.StrToROptionInLocation(e.RRule, e.Start.Location())
	if err != nil {
		// An unreadable rule still shows the first occurrence.
		cp := *e
		cp.RRule = ""
		return cp.occurrences(from, to)
	}
	opt.Dtstart = e.Start
	rule, err := rrule.NewRRule(*opt)
	if err != nil {
		cp := *e
		cp.RRule = ""
		return cp.occurrences(from, to)
	}
	var set rrule.Set
	set.RRule(rule)
	for _, x := range e.ExDates {
		set.ExDate(x)
	}
	var out []Occurrence
	starts := set.Between(from.Add(-dur), to, true)
	for _, s := range starts {
		if len(out) >= maxOccurrences {
			break
		}
		end := s.Add(dur)
		if e.AllDay {
			// Calendar days, not hours: a DST change mustn't shift them.
			days := int(e.End.Sub(e.Start).Hours()/24 + 0.5)
			end = s.AddDate(0, 0, days)
		}
		if s.Before(to) && (end.After(from) || (dur == 0 && !s.Before(from))) {
			out = append(out, Occurrence{Event: e, Start: s, End: end})
		}
	}
	return out
}

// expand returns every occurrence of events overlapping [from, to), in
// start order, all-day events first on each day.
func expand(events []Event, from, to time.Time) []Occurrence {
	var out []Occurrence
	for i := range events {
		out = append(out, events[i].occurrences(from, to)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		if out[i].Event.AllDay != out[j].Event.AllDay {
			return out[i].Event.AllDay
		}
		return out[i].Event.Summary < out[j].Event.Summary
	})
	return out
}

// ruleSummary describes a recurrence rule in words, for the common rules
// the event form produces; anything else is shown as "Custom repeat".
func ruleSummary(rule string, start time.Time) string {
	if rule == "" {
		return ""
	}
	opt, err := rrule.StrToROption(rule)
	if err != nil {
		return "Custom repeat"
	}
	every := func(one, many string) string {
		if opt.Interval > 1 {
			return fmt.Sprintf("Every %d %s", opt.Interval, many)
		}
		return one
	}
	var s string
	switch opt.Freq {
	case rrule.DAILY:
		s = every("Daily", "days")
	case rrule.WEEKLY:
		if len(opt.Byweekday) == 5 && !hasWeekend(opt.Byweekday) && opt.Interval <= 1 {
			s = "Every weekday"
			break
		}
		s = every("Weekly", "weeks")
		if len(opt.Byweekday) > 0 {
			var days []string
			for _, d := range opt.Byweekday {
				days = append(days, weekdayNames[d.Day()][:3])
			}
			s += " on " + strings.Join(days, ", ")
		} else {
			s += " on " + start.Weekday().String()
		}
	case rrule.MONTHLY:
		s = every("Monthly", "months") + fmt.Sprintf(" on day %d", start.Day())
	case rrule.YEARLY:
		s = every("Yearly", "years") + " on " + start.Format("January 2")
	default:
		return "Custom repeat"
	}
	switch {
	case opt.Count > 0:
		s += fmt.Sprintf(", %d times", opt.Count)
	case !opt.Until.IsZero():
		s += ", until " + opt.Until.Format("Jan 2, 2006")
	}
	return s
}

// weekdayNames is indexed by rrule's weekday number (Monday = 0).
var weekdayNames = []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

func hasWeekend(days []rrule.Weekday) bool {
	for _, d := range days {
		if d.Day() >= 5 {
			return true
		}
	}
	return false
}
