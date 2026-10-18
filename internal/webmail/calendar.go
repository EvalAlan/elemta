package webmail

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

// defaultCalendar is the calendar an event belongs to when none is named.
const defaultCalendar = "Calendar"

// events returns every stored event, read in loc (the user's zone).
func (s *Server) events(ctx context.Context, sess *Session, loc *time.Location) ([]Event, error) {
	var out []Event
	err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollCalendar)
		if err != nil {
			return err
		}
		for _, o := range objs {
			cal, err := decodeCalendar(o.Data, loc)
			if err != nil {
				continue
			}
			for _, e := range cal.Events {
				// Storage is keyed by the object ID; an event carried in
				// an object named otherwise (a split override) keeps its own.
				if e.Calendar == "" {
					e.Calendar = defaultCalendar
				}
				out = append(out, e)
			}
		}
		return nil
	})
	return out, err
}

func (s *Server) putEvent(ctx context.Context, sess *Session, e Event) error {
	e.Modified = s.now().UTC()
	data, err := encodeCalendar("", s.now(), e.toComponent(s.now()))
	if err != nil {
		return err
	}
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		return st.PutObject(ctx, CollCalendar, Object{ID: e.UID, Title: e.Summary, ContentType: "text/calendar", Data: data})
	})
}

func (s *Server) deleteEvent(ctx context.Context, sess *Session, uid string) error {
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		return st.DeleteObject(ctx, CollCalendar, uid)
	})
}

func findEvent(events []Event, uid string) *Event {
	for i := range events {
		if events[i].UID == uid {
			return &events[i]
		}
	}
	return nil
}

// calClass gives each calendar one of eight colours, from its name.
func calClass(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(name)))
	return "cal-" + strconv.Itoa(int(h.Sum32()%8))
}

// ---- views -----------------------------------------------------------------

type calendarView struct {
	View      string // month, week, day or agenda
	Date      time.Time
	Today     time.Time
	Title     string
	PrevURL   string
	NextURL   string
	TodayURL  string
	Weekdays  []string
	Weeks     [][]calDay
	Days      []calDay
	Hours     []int
	Agenda    []calDay
	Mini      miniMonth
	Calendars []string
	ScrollTo  int
	Event     *eventDetail
	Form      *eventForm
	// NowQ is the current quarter hour, for the red line in day and week.
	NowQ int
}

type calDay struct {
	Date   time.Time
	Other  bool // outside the month being shown
	Today  bool
	AllDay []calItem
	Timed  []calItem
	More   int
	URL    string
	NewURL string
}

type calItem struct {
	Occ       Occurrence
	Class     string
	PosClass  string // qN dN laneI lanesN, for the time grid
	URL       string
	TimeLabel string
	Continues bool // an all-day or multi-day item carried over from an earlier day
}

type miniMonth struct {
	Title string
	Weeks [][]miniDay
}

type miniDay struct {
	Day    int
	URL    string
	Other  bool
	Today  bool
	Chosen bool
}

func dayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// weekStart is the first day of the week containing t.
func weekStart(t time.Time, first int) time.Time {
	t = dayStart(t)
	back := (int(t.Weekday()) - first + 7) % 7
	return t.AddDate(0, 0, -back)
}

func calURL(view string, d time.Time) string {
	return "/calendar?" + url.Values{"view": {view}, "date": {d.Format("2006-01-02")}}.Encode()
}

func eventURL(uid string, occ time.Time) string {
	v := url.Values{"uid": {uid}}
	if !occ.IsZero() {
		v.Set("occ", strconv.FormatInt(occ.Unix(), 10))
	}
	return "/calendar/event?" + v.Encode()
}

func (s *Server) calendarPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	prefs := s.prefsCached(sess)
	q := r.URL.Query()
	now := s.now().In(loc)
	today := dayStart(now)
	date := today
	if d, err := time.ParseInLocation("2006-01-02", q.Get("date"), loc); err == nil {
		date = d
	}
	view := q.Get("view")
	switch view {
	case "month", "week", "day", "agenda":
	default:
		view = prefs.CalendarView
		if view == "" {
			view = "month"
		}
	}
	events, err := s.calendarEvents(r.Context(), sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	cv := s.buildCalendar(view, date, today, now, prefs, events)
	v := view2(sess, "Calendar", cv)
	v.Notice = notices[q.Get("n")]
	s.render(w, "calendar.html", http.StatusOK, v)
}

func view2(sess *Session, title string, cv *calendarView) view {
	return view{Title: title, Session: sess, App: "calendar", Calendar: cv}
}

// buildCalendar lays out one view of the calendar around date.
func (s *Server) buildCalendar(view string, date, today, now time.Time, prefs Settings, events []Event) *calendarView {
	h24 := prefs.Uses24h()
	cv := &calendarView{View: view, Date: date, Today: today, TodayURL: calURL(view, today), ScrollTo: 7}
	first := prefs.WeekStart
	for i := 0; i < 7; i++ {
		cv.Weekdays = append(cv.Weekdays, time.Weekday((first + i) % 7).String()[:3])
	}
	cv.Calendars = calendarNames(events)
	cv.NowQ = now.Hour()*4 + now.Minute()/15

	item := func(o Occurrence, day time.Time) calItem {
		it := calItem{Occ: o, Class: calClass(o.Event.Calendar), URL: eventURL(o.Event.UID, o.Start)}
		if !o.Event.AllDay {
			it.TimeLabel = clock(h24, o.Start)
		}
		it.Continues = o.Start.Before(day)
		return it
	}
	// fill puts occurrences into the days they touch.
	fill := func(days []calDay, occs []Occurrence) {
		for i := range days {
			d := days[i].Date
			next := d.AddDate(0, 0, 1)
			for _, o := range occs {
				if !(o.Start.Before(next) && (o.End.After(d) || (o.End.Equal(o.Start) && !o.Start.Before(d)))) {
					continue
				}
				// A timed event spanning midnight shows in the all-day row
				// of each day after the first, like most calendars do.
				if o.Event.AllDay || !sameDay(o.Start, o.End.Add(-time.Nanosecond)) && o.End.Sub(o.Start) >= 24*time.Hour {
					days[i].AllDay = append(days[i].AllDay, item(o, d))
				} else {
					days[i].Timed = append(days[i].Timed, item(o, d))
				}
			}
		}
	}

	switch view {
	case "month":
		monthStart := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, date.Location())
		gridStart := weekStart(monthStart, first)
		gridEnd := gridStart.AddDate(0, 0, 42)
		cv.Title = date.Format("January 2006")
		cv.PrevURL = calURL(view, monthStart.AddDate(0, -1, 0))
		cv.NextURL = calURL(view, monthStart.AddDate(0, 1, 0))
		var days []calDay
		for d := gridStart; d.Before(gridEnd); d = d.AddDate(0, 0, 1) {
			days = append(days, calDay{Date: d, Other: d.Month() != date.Month(), Today: sameDay(d, today), URL: calURL("day", d), NewURL: newEventURL(d, -1)})
		}
		fill(days, expand(events, gridStart, gridEnd))
		for i := range days {
			// Month cells hold three items; the rest is a "+N more" link.
			all := append(days[i].AllDay, days[i].Timed...)
			if len(all) > 3 {
				days[i].More = len(all) - 3
				all = all[:3]
			}
			days[i].AllDay, days[i].Timed = all, nil
		}
		for i := 0; i < len(days); i += 7 {
			week := days[i : i+7]
			// Drop a trailing week that lies wholly in the next month.
			if i >= 35 && week[0].Other {
				break
			}
			cv.Weeks = append(cv.Weeks, week)
		}
	case "week", "day":
		n, start := 7, weekStart(date, first)
		if view == "day" {
			n, start = 1, date
			cv.Title = date.Format("Monday, January 2, 2006")
		} else {
			end := start.AddDate(0, 0, 6)
			if start.Month() == end.Month() {
				cv.Title = start.Format("January 2") + " – " + end.Format("2, 2006")
			} else {
				cv.Title = start.Format("Jan 2") + " – " + end.Format("Jan 2, 2006")
			}
		}
		cv.PrevURL = calURL(view, start.AddDate(0, 0, -n))
		cv.NextURL = calURL(view, start.AddDate(0, 0, n))
		for i := 0; i < n; i++ {
			d := start.AddDate(0, 0, i)
			cv.Days = append(cv.Days, calDay{Date: d, Today: sameDay(d, today), URL: calURL("day", d), NewURL: newEventURL(d, -1)})
		}
		fill(cv.Days, expand(events, start, start.AddDate(0, 0, n)))
		earliest := 24
		for i := range cv.Days {
			layoutDay(cv.Days[i].Timed, cv.Days[i].Date)
			for _, it := range cv.Days[i].Timed {
				if h := it.Occ.Start.Hour(); sameDay(it.Occ.Start, cv.Days[i].Date) && h < earliest {
					earliest = h
				}
			}
		}
		cv.ScrollTo = min(7, earliest)
		for h := 0; h < 24; h++ {
			cv.Hours = append(cv.Hours, h)
		}
	case "agenda":
		start := date
		end := start.AddDate(0, 0, 30)
		cv.Title = start.Format("Jan 2") + " – " + end.AddDate(0, 0, -1).Format("Jan 2, 2006")
		cv.PrevURL = calURL(view, start.AddDate(0, 0, -30))
		cv.NextURL = calURL(view, end)
		var days []calDay
		for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
			days = append(days, calDay{Date: d, Today: sameDay(d, today), URL: calURL("day", d)})
		}
		fill(days, expand(events, start, end))
		for _, d := range days {
			if len(d.AllDay)+len(d.Timed) > 0 {
				d.AllDay = append(d.AllDay, d.Timed...)
				d.Timed = nil
				cv.Agenda = append(cv.Agenda, d)
			}
		}
	}
	cv.Mini = buildMini(date, today, first, view)
	return cv
}

// layoutDay positions a day's timed items on the quarter-hour grid and
// splits overlapping ones into side-by-side lanes.
func layoutDay(items []calItem, day time.Time) {
	sort.SliceStable(items, func(i, j int) bool { return items[i].Occ.Start.Before(items[j].Occ.Start) })
	type placed struct{ q, d, lane int }
	pos := make([]placed, len(items))
	for i, it := range items {
		start := it.Occ.Start
		if start.Before(day) {
			start = day
		}
		end := it.Occ.End
		if next := day.AddDate(0, 0, 1); end.After(next) {
			end = next
		}
		q := start.Hour()*4 + start.Minute()/15
		d := int(end.Sub(start).Minutes()+14) / 15
		pos[i] = placed{q: q, d: max(2, min(d, 96-q))}
	}
	// Greedy lanes within clusters of mutually overlapping items.
	for i := 0; i < len(items); {
		j, clusterEnd := i, pos[i].q+pos[i].d
		var laneEnds []int
		for ; j < len(items) && pos[j].q < clusterEnd; j++ {
			lane := -1
			for l, e := range laneEnds {
				if e <= pos[j].q {
					lane = l
					break
				}
			}
			if lane < 0 {
				lane = len(laneEnds)
				laneEnds = append(laneEnds, 0)
			}
			laneEnds[lane] = pos[j].q + pos[j].d
			pos[j].lane = lane
			clusterEnd = max(clusterEnd, pos[j].q+pos[j].d)
		}
		lanes := min(len(laneEnds), 4)
		for k := i; k < j; k++ {
			cls := fmt.Sprintf("q%d d%d", pos[k].q, pos[k].d)
			if pos[k].d <= 2 {
				cls += " short"
			}
			if lanes > 1 {
				cls += fmt.Sprintf(" lanes%d lane%d", lanes, min(pos[k].lane, lanes-1))
			}
			items[k].PosClass = cls
		}
		i = j
	}
}

func buildMini(date, today time.Time, first int, view string) miniMonth {
	monthStart := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, date.Location())
	start := weekStart(monthStart, first)
	m := miniMonth{Title: date.Format("January 2006")}
	target := view
	if target == "agenda" || target == "month" {
		target = "day"
	}
	for w := 0; w < 6; w++ {
		var week []miniDay
		for i := 0; i < 7; i++ {
			d := start.AddDate(0, 0, w*7+i)
			week = append(week, miniDay{Day: d.Day(), URL: calURL(target, d), Other: d.Month() != date.Month(), Today: sameDay(d, today), Chosen: sameDay(d, date)})
		}
		if w >= 4 && week[0].Other {
			break
		}
		m.Weeks = append(m.Weeks, week)
	}
	return m
}

func calendarNames(events []Event) []string {
	seen := map[string]bool{defaultCalendar: true}
	out := []string{defaultCalendar}
	for _, e := range events {
		if e.Calendar != "" && !seen[e.Calendar] {
			seen[e.Calendar] = true
			out = append(out, e.Calendar)
		}
	}
	sort.Strings(out[1:])
	return out
}

func newEventURL(d time.Time, hour int) string {
	v := url.Values{"new": {"1"}, "date": {d.Format("2006-01-02")}}
	if hour >= 0 {
		v.Set("hour", strconv.Itoa(hour))
	}
	return "/calendar/event?" + v.Encode()
}

// ---- one event -------------------------------------------------------------

type eventDetail struct {
	Event      *Event
	Occ        Occurrence
	Repeat     string
	Organizer  bool
	MyStatus   string
	Conflicts  []Occurrence
	Class      string
	ICSURL     string
	OccURL     string
	DeleteNote string
}

type eventForm struct {
	UID, Summary, Location, Description, URL string
	StartDate, StartTime, EndDate, EndTime   string
	AllDay                                   bool
	Repeat                                   string // "", daily, weekdays, weekly, monthly, yearly, custom
	Interval                                 int
	Days                                     map[int]bool
	Ends                                     string // never, until, count
	Until                                    string
	Count                                    int
	CustomRule                               string
	Calendar                                 string
	Calendars                                []string
	Reminder                                 int
	Busy                                     bool
	Attendees                                string
	Notify                                   bool
	Occ                                      int64 // the occurrence being edited, for "this one only"
	Recurring                                bool
	Problem                                  string
	WeekdayOpts                              []weekdayOpt
}

type weekdayOpt struct {
	Value   int // rrule weekday, Monday = 0
	Label   string
	Checked bool
}

var reminderChoices = []struct {
	Minutes int
	Label   string
}{{-1, "No reminder"}, {0, "At the start"}, {5, "5 minutes before"}, {10, "10 minutes before"}, {15, "15 minutes before"}, {30, "30 minutes before"}, {60, "1 hour before"}, {120, "2 hours before"}, {1440, "1 day before"}, {10080, "1 week before"}}

func (s *Server) eventPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	prefs := s.prefsCached(sess)
	q := r.URL.Query()
	now := s.now().In(loc)
	events, err := s.calendarEvents(r.Context(), sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	date := dayStart(now)
	if d, err := time.ParseInLocation("2006-01-02", q.Get("date"), loc); err == nil {
		date = d
	}
	var occ time.Time
	if n, err := strconv.ParseInt(q.Get("occ"), 10, 64); err == nil {
		occ = time.Unix(n, 0).In(loc)
	}
	ev := findEvent(events, q.Get("uid"))
	if ev != nil && occ.IsZero() {
		occ = ev.Start
	}
	if ev != nil {
		date = dayStart(occ.In(loc))
	}
	view := prefs.CalendarView
	if view == "" {
		view = "month"
	}
	cv := s.buildCalendar("agenda", date, dayStart(now), now, prefs, nil)
	cv.View = view
	cv.Calendars = calendarNames(events)
	cv.TodayURL = calURL(view, dayStart(now))
	cv.PrevURL = calURL(view, date)
	v := view2(sess, "Calendar", cv)
	v.Notice = notices[q.Get("n")]

	switch {
	case q.Get("new") == "1":
		hour := 9
		if h, err := strconv.Atoi(q.Get("hour")); err == nil && h >= 0 && h < 24 {
			hour = h
		} else if sameDay(date, now) {
			hour = min(now.Hour()+1, 23)
		}
		start := date.Add(time.Duration(hour) * time.Hour)
		f := &eventForm{
			StartDate: start.Format("2006-01-02"), StartTime: start.Format("15:04"),
			EndDate: start.Add(time.Hour).Format("2006-01-02"), EndTime: start.Add(time.Hour).Format("15:04"),
			Interval: 1, Ends: "never", Calendar: defaultCalendar, Reminder: 15, Busy: true, Notify: true,
			Summary: q.Get("title"),
		}
		if q.Get("allday") == "1" {
			f.AllDay = true
		}
		cv.Form = s.finishForm(f, events, start)
		v.Title = "New event"
	case ev == nil:
		s.fail(w, r, sess, ErrNotFound)
		return
	case q.Get("edit") == "1" && !ev.ReadOnly:
		cv.Form = s.finishForm(formFromEvent(ev, occ, loc), events, ev.Start)
		v.Title = "Edit " + ev.Summary
	default:
		o := Occurrence{Event: ev, Start: occ, End: occ.Add(ev.Duration())}
		if ev.AllDay {
			days := int(ev.End.Sub(ev.Start).Hours()/24 + 0.5)
			o.End = occ.AddDate(0, 0, days)
		}
		d := &eventDetail{
			Event: ev, Occ: o, Repeat: ruleSummary(ev.RRule, ev.Start), Organizer: ev.IsOrganizer(sess.Address),
			Class: calClass(ev.Calendar), ICSURL: "/calendar/export?uid=" + url.QueryEscape(ev.UID),
			OccURL: eventURL(ev.UID, occ),
		}
		for _, a := range ev.Attendees {
			if strings.EqualFold(a.Email, sess.Address) {
				d.MyStatus = a.Status
			}
		}
		if ev.Busy {
			for _, c := range expand(events, o.Start, o.End) {
				if c.Event.UID != ev.UID && c.Event.Busy && !c.Event.AllDay && !o.Event.AllDay {
					d.Conflicts = append(d.Conflicts, c)
				}
			}
		}
		cv.Event = d
		v.Title = ev.Summary
	}
	s.render(w, "calendar.html", http.StatusOK, v)
}

func (s *Server) finishForm(f *eventForm, events []Event, start time.Time) *eventForm {
	f.Calendars = calendarNames(events)
	if f.Days == nil {
		f.Days = map[int]bool{rruleWeekday(start.Weekday()): true}
	}
	for i, name := range weekdayNames {
		f.WeekdayOpts = append(f.WeekdayOpts, weekdayOpt{Value: i, Label: name[:3], Checked: f.Days[i]})
	}
	if f.Interval < 1 {
		f.Interval = 1
	}
	return f
}

// rruleWeekday converts Go's Sunday-first weekday to rrule's Monday-first.
func rruleWeekday(d time.Weekday) int { return (int(d) + 6) % 7 }

func formFromEvent(e *Event, occ time.Time, loc *time.Location) *eventForm {
	start, end := e.Start.In(loc), e.End.In(loc)
	if e.AllDay {
		start, end = e.Start, e.End.AddDate(0, 0, -1)
	}
	f := &eventForm{
		UID: e.UID, Summary: e.Summary, Location: e.Location, Description: e.Description, URL: e.URL,
		StartDate: start.Format("2006-01-02"), StartTime: start.Format("15:04"),
		EndDate: end.Format("2006-01-02"), EndTime: end.Format("15:04"), AllDay: e.AllDay,
		Interval: 1, Ends: "never", Calendar: e.Calendar, Reminder: e.Reminder, Busy: e.Busy,
		Recurring: e.Recurring(), Occ: occ.Unix(),
	}
	var att []string
	for _, a := range e.Attendees {
		att = append(att, formatAddress(Address{Name: a.Name, Email: a.Email}))
	}
	f.Attendees = strings.Join(att, ", ")
	if e.RRule == "" {
		return f
	}
	opt, err := rrule.StrToROption(e.RRule)
	if err != nil {
		f.Repeat, f.CustomRule = "custom", e.RRule
		return f
	}
	f.Interval = max(opt.Interval, 1)
	switch opt.Freq {
	case rrule.DAILY:
		f.Repeat = "daily"
	case rrule.WEEKLY:
		f.Repeat = "weekly"
		f.Days = map[int]bool{}
		for _, d := range opt.Byweekday {
			f.Days[d.Day()] = true
		}
		if len(opt.Byweekday) == 5 && !hasWeekend(opt.Byweekday) && f.Interval == 1 {
			f.Repeat = "weekdays"
		}
	case rrule.MONTHLY:
		f.Repeat = "monthly"
	case rrule.YEARLY:
		f.Repeat = "yearly"
	default:
		f.Repeat, f.CustomRule = "custom", e.RRule
	}
	// Rules with parts the form can't show are kept verbatim.
	if len(opt.Bymonthday) > 0 || len(opt.Bysetpos) > 0 || len(opt.Byyearday) > 0 || (opt.Freq == rrule.MONTHLY && len(opt.Byweekday) > 0) {
		f.Repeat, f.CustomRule = "custom", e.RRule
	}
	switch {
	case opt.Count > 0:
		f.Ends, f.Count = "count", opt.Count
	case !opt.Until.IsZero():
		f.Ends, f.Until = "until", opt.Until.In(loc).Format("2006-01-02")
	}
	return f
}

// buildRule turns the form's repeat fields into an RRULE.
func buildRule(f *eventForm, start time.Time, loc *time.Location) (string, error) {
	var parts []string
	switch f.Repeat {
	case "":
		return "", nil
	case "custom":
		if _, err := rrule.StrToROption(f.CustomRule); err != nil {
			return "", errors.New("the custom repeat rule isn't valid")
		}
		return f.CustomRule, nil
	case "daily":
		parts = append(parts, "FREQ=DAILY")
	case "weekdays":
		parts = append(parts, "FREQ=WEEKLY", "BYDAY=MO,TU,WE,TH,FR")
	case "weekly":
		parts = append(parts, "FREQ=WEEKLY")
		codes := []string{"MO", "TU", "WE", "TH", "FR", "SA", "SU"}
		var days []string
		for i, c := range codes {
			if f.Days[i] {
				days = append(days, c)
			}
		}
		if len(days) == 0 {
			days = append(days, codes[rruleWeekday(start.Weekday())])
		}
		parts = append(parts, "BYDAY="+strings.Join(days, ","))
	case "monthly":
		parts = append(parts, "FREQ=MONTHLY")
	case "yearly":
		parts = append(parts, "FREQ=YEARLY")
	default:
		return "", errors.New("unknown repeat choice")
	}
	if f.Interval > 1 && f.Repeat != "weekdays" {
		parts = append(parts, "INTERVAL="+strconv.Itoa(f.Interval))
	}
	switch f.Ends {
	case "count":
		if f.Count < 1 || f.Count > 1000 {
			return "", errors.New("repeat between 1 and 1,000 times")
		}
		parts = append(parts, "COUNT="+strconv.Itoa(f.Count))
	case "until":
		u, err := time.ParseInLocation("2006-01-02", f.Until, loc)
		if err != nil || u.Before(dayStart(start)) {
			return "", errors.New("the repeat end date must be on or after the start")
		}
		// UNTIL is inclusive: the end of that day, in UTC as RFC 5545 asks.
		parts = append(parts, "UNTIL="+u.AddDate(0, 0, 1).Add(-time.Second).UTC().Format("20060102T150405Z"))
	}
	return strings.Join(parts, ";"), nil
}

func parseEventForm(r *http.Request) *eventForm {
	f := &eventForm{
		UID: r.PostFormValue("uid"), Summary: strings.TrimSpace(r.PostFormValue("summary")),
		Location: strings.TrimSpace(r.PostFormValue("location")), Description: strings.TrimSpace(normaliseText(r.PostFormValue("description"))),
		URL:       strings.TrimSpace(r.PostFormValue("url")),
		StartDate: r.PostFormValue("start_date"), StartTime: r.PostFormValue("start_time"),
		EndDate: r.PostFormValue("end_date"), EndTime: r.PostFormValue("end_time"),
		AllDay: r.PostFormValue("allday") == "1", Repeat: r.PostFormValue("repeat"),
		Ends: r.PostFormValue("ends"), Until: r.PostFormValue("until"), CustomRule: r.PostFormValue("custom_rule"),
		Calendar: strings.TrimSpace(r.PostFormValue("calendar")), Busy: r.PostFormValue("busy") != "free",
		Attendees: r.PostFormValue("attendees"), Notify: r.PostFormValue("notify") == "1",
		Days: map[int]bool{},
	}
	f.Interval, _ = strconv.Atoi(r.PostFormValue("interval"))
	f.Count, _ = strconv.Atoi(r.PostFormValue("count"))
	f.Reminder, _ = strconv.Atoi(r.PostFormValue("reminder"))
	if r.PostFormValue("reminder") == "" {
		f.Reminder = -1
	}
	f.Occ, _ = strconv.ParseInt(r.PostFormValue("occ"), 10, 64)
	f.Recurring = r.PostFormValue("recurring") == "1"
	for _, d := range r.PostForm["byday"] {
		if n, err := strconv.Atoi(d); err == nil && n >= 0 && n < 7 {
			f.Days[n] = true
		}
	}
	if f.Calendar == "" {
		f.Calendar = defaultCalendar
	}
	return f
}

// eventFromForm validates the form and builds the event it describes.
func eventFromForm(f *eventForm, loc *time.Location) (Event, error) {
	e := Event{
		UID: f.UID, Summary: f.Summary, Location: f.Location, Description: f.Description, URL: f.URL,
		AllDay: f.AllDay, Calendar: f.Calendar, Reminder: f.Reminder, Busy: f.Busy, Status: "CONFIRMED",
	}
	if e.Summary == "" {
		e.Summary = "(no title)"
	}
	if len(e.Summary) > 500 || len(e.Description) > 20000 || len(e.Calendar) > 60 {
		return e, errors.New("the title, description or calendar name is too long")
	}
	if e.URL != "" && !strings.HasPrefix(e.URL, "https://") && !strings.HasPrefix(e.URL, "http://") {
		return e, errors.New("the link must start with https:// or http://")
	}
	sd, err := time.ParseInLocation("2006-01-02", f.StartDate, loc)
	if err != nil {
		return e, errors.New("choose a start date")
	}
	ed, err := time.ParseInLocation("2006-01-02", f.EndDate, loc)
	if err != nil {
		ed = sd
	}
	if e.AllDay {
		if ed.Before(sd) {
			return e, errors.New("the event ends before it starts")
		}
		e.Start, e.End = sd, ed.AddDate(0, 0, 1)
	} else {
		st, err1 := time.Parse("15:04", f.StartTime)
		et, err2 := time.Parse("15:04", f.EndTime)
		if err1 != nil || err2 != nil {
			return e, errors.New("choose a start and end time")
		}
		e.Start = time.Date(sd.Year(), sd.Month(), sd.Day(), st.Hour(), st.Minute(), 0, 0, loc)
		e.End = time.Date(ed.Year(), ed.Month(), ed.Day(), et.Hour(), et.Minute(), 0, 0, loc)
		if e.End.Before(e.Start) {
			return e, errors.New("the event ends before it starts")
		}
	}
	if e.End.Sub(e.Start) > 366*24*time.Hour {
		return e, errors.New("events can last at most a year")
	}
	rule, err := buildRule(f, e.Start, loc)
	if err != nil {
		return e, err
	}
	e.RRule = rule
	if strings.TrimSpace(f.Attendees) != "" {
		list, err := parseList(f.Attendees)
		if err != nil {
			return e, errors.New("check the guest addresses; separate them with commas")
		}
		if len(list) > 200 {
			return e, errors.New("an event can have at most 200 guests")
		}
		for _, a := range list {
			e.Attendees = append(e.Attendees, Attendee{Email: a.Email, Name: a.Name, Status: "NEEDS-ACTION"})
		}
	}
	return e, nil
}

func (s *Server) eventSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	ctx := r.Context()
	op := r.PostFormValue("op")
	events, err := s.events(ctx, sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	switch op {
	case "delete", "delete-occurrence":
		s.deleteEventSubmit(w, r, sess, events, op == "delete-occurrence")
		return
	case "save":
	default:
		s.fail(w, r, sess, ErrNotFound)
		return
	}

	f := parseEventForm(r)
	e, err := eventFromForm(f, loc)
	if err != nil {
		f.Problem = strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
		cv := &calendarView{View: "month", Form: s.finishForm(f, events, time.Now().In(loc)), Calendars: calendarNames(events), TodayURL: "/calendar", PrevURL: "/calendar"}
		cv.Mini = buildMini(dayStart(time.Now().In(loc)), dayStart(time.Now().In(loc)), s.prefsCached(sess).WeekStart, "month")
		s.render(w, "calendar.html", http.StatusBadRequest, view2(sess, "Event", cv))
		return
	}

	existing := findEvent(events, f.UID)
	scope := r.PostFormValue("scope")
	switch {
	case existing == nil:
		e.UID = newObjectID() + "@" + domainOf(sess.Address)
	case existing.Recurring() && scope == "this" && f.Occ != 0:
		// Editing one occurrence: cut it out of the series and save it as
		// an event of its own.
		occ := time.Unix(f.Occ, 0).In(existing.Start.Location())
		series := *existing
		series.ExDates = append(series.ExDates, occ)
		series.Sequence++
		if err := s.putEvent(ctx, sess, series); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		e.UID = existing.UID + "-" + occ.UTC().Format("20060102T150405Z")
		e.RRule = ""
		e.Organizer = existing.Organizer
	default:
		e.UID = existing.UID
		e.ExDates = existing.ExDates
		e.Sequence = existing.Sequence + 1
		e.Organizer = existing.Organizer
		// Keep the replies already received from guests who stay invited.
		prev := map[string]string{}
		for _, a := range existing.Attendees {
			prev[strings.ToLower(a.Email)] = a.Status
		}
		for i := range e.Attendees {
			if st, ok := prev[strings.ToLower(e.Attendees[i].Email)]; ok {
				e.Attendees[i].Status = st
			}
		}
		if existing.RRule != e.RRule {
			e.ExDates = nil
		}
	}
	if len(e.Attendees) > 0 && e.Organizer == nil {
		prefs := s.prefsCached(sess)
		e.Organizer = &Attendee{Email: sess.Address, Name: prefs.DisplayName}
	}
	if err := s.putEvent(ctx, sess, e); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	notice := "event-saved"
	if f.Notify && len(e.Attendees) > 0 && e.IsOrganizer(sess.Address) {
		var removed []Attendee
		if existing != nil {
			keep := map[string]bool{}
			for _, a := range e.Attendees {
				keep[strings.ToLower(a.Email)] = true
			}
			for _, a := range existing.Attendees {
				if !keep[strings.ToLower(a.Email)] {
					removed = append(removed, a)
				}
			}
		}
		notice = "invites-sent"
		if err := s.sendInvites(ctx, sess, e, "REQUEST", e.Attendees); err != nil {
			s.log.Warn("webmail: send invitations", "user", sess.User, "error", err)
			notice = "invite-failed"
		}
		if len(removed) > 0 {
			if err := s.sendInvites(ctx, sess, e, "CANCEL", removed); err != nil {
				s.log.Warn("webmail: send cancellations", "user", sess.User, "error", err)
			}
		}
	}
	http.Redirect(w, r, eventURL(e.UID, time.Time{})+"&n="+notice, http.StatusSeeOther)
}

func (s *Server) deleteEventSubmit(w http.ResponseWriter, r *http.Request, sess *Session, events []Event, oneOccurrence bool) {
	ctx := r.Context()
	ev := findEvent(events, r.PostFormValue("uid"))
	if ev == nil {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	back := calURL("month", ev.Start)
	occ, _ := strconv.ParseInt(r.PostFormValue("occ"), 10, 64)
	if oneOccurrence && ev.Recurring() && occ != 0 {
		cp := *ev
		cp.ExDates = append(cp.ExDates, time.Unix(occ, 0).In(ev.Start.Location()))
		cp.Sequence++
		if err := s.putEvent(ctx, sess, cp); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		http.Redirect(w, r, calURL("month", time.Unix(occ, 0))+"&n=event-deleted", http.StatusSeeOther)
		return
	}
	if err := s.deleteEvent(ctx, sess, ev.UID); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	// Guests hear about a cancelled meeting; a declined invitation that the
	// user only removes from their own calendar tells nobody.
	if len(ev.Attendees) > 0 && ev.IsOrganizer(sess.Address) && r.PostFormValue("notify") == "1" {
		cp := *ev
		cp.Sequence++
		cp.Status = "CANCELLED"
		if err := s.sendInvites(ctx, sess, cp, "CANCEL", cp.Attendees); err != nil {
			s.log.Warn("webmail: send cancellations", "user", sess.User, "error", err)
		}
	}
	http.Redirect(w, r, back+"&n=event-deleted", http.StatusSeeOther)
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "localhost"
}

// ---- import and export -----------------------------------------------------

// calendarExport downloads every event (or one, with ?uid=) as .ics.
func (s *Server) calendarExport(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	events, err := s.events(r.Context(), sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	uid := r.URL.Query().Get("uid")
	var comps []*ical.Component
	name := "calendar.ics"
	for _, e := range events {
		if uid != "" && e.UID != uid {
			continue
		}
		comps = append(comps, e.toComponent(s.now()))
		if uid != "" {
			name = "event.ics"
		}
	}
	if len(comps) == 0 {
		if uid != "" {
			s.fail(w, r, sess, ErrNotFound)
			return
		}
		// An empty VCALENDAR is invalid; export a valid file with no events
		// by way of an empty-bodied calendar the encoder accepts.
		w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		_, _ = io.WriteString(w, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:"+prodID+"\r\nEND:VCALENDAR\r\n")
		return
	}
	data, err := encodeCalendar("", s.now(), comps...)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Cache-Control", "private, no-store")
	// #nosec G705 -- an iCalendar download served as an attachment with nosniff
	_, _ = w.Write(data)
}

// maxImportEvents bounds one import, like maxImportCards.
const maxImportEvents = 5000

// calendarImport adds the events in an uploaded .ics file. Events keep
// their UIDs, so importing the same file again updates rather than
// duplicates.
func (s *Server) calendarImport(w http.ResponseWriter, r *http.Request, sess *Session) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) == 0 {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Choose an .ics file to import.")
		return
	}
	f, err := r.MultipartForm.File["file"][0].Open()
	if err != nil {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "The file couldn't be read.")
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 20<<20))
	if err != nil {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "The file couldn't be read.")
		return
	}
	cal, err := decodeCalendar(data, s.loc(sess))
	if err != nil {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "That file isn't an iCalendar (.ics) file with events in it, or it is damaged.")
		return
	}
	target := strings.TrimSpace(r.PostFormValue("calendar"))
	for i, e := range cal.Events {
		if i >= maxImportEvents {
			break
		}
		if target != "" {
			e.Calendar = target
		}
		if err := s.putEvent(r.Context(), sess, e); err != nil {
			s.fail(w, r, sess, err)
			return
		}
	}
	http.Redirect(w, r, "/calendar?n=events-imported", http.StatusSeeOther)
}
