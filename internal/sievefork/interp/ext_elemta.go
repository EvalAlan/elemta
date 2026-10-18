package interp

// Extensions added in this fork for Elemta (see ../FORK.md): the regex
// match type, the date extension's date and currentdate tests (RFC 5260)
// and the vacation action (RFC 5230, with RFC 6131 :seconds). The mailbox
// extension's :create tag is in load_action.go.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/sievefork/parser"
)

// maxRegexLen bounds user-supplied regular expressions. Go's engine is
// linear in the input, so a long pattern only costs compile time.
const maxRegexLen = 1024

func compileRegexKey(key string, caseFold bool) (CompiledMatcher, error) {
	if len(key) > maxRegexLen {
		return CompiledMatcher{}, fmt.Errorf("regex longer than %d bytes", maxRegexLen)
	}
	if caseFold {
		key = "(?i)" + key
	}
	return compileMatcherRegex(key, false)
}

// ---- date and currentdate (RFC 5260) --------------------------------------

var dateParts = map[string]bool{
	"year": true, "month": true, "day": true, "date": true, "julian": true, "hour": true, "minute": true,
	"second": true, "time": true, "iso8601": true, "std11": true, "zone": true, "weekday": true,
}

// datePart renders one RFC 5260 date-part of t.
func datePart(t time.Time, part string) string {
	switch part {
	case "year":
		return fmt.Sprintf("%04d", t.Year())
	case "month":
		return fmt.Sprintf("%02d", int(t.Month()))
	case "day":
		return fmt.Sprintf("%02d", t.Day())
	case "date":
		return t.Format("2006-01-02")
	case "julian":
		// Days since 1858-11-17 (the Modified Julian Day epoch).
		epoch := time.Date(1858, 11, 17, 0, 0, 0, 0, time.UTC)
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		return strconv.Itoa(int(day.Sub(epoch).Hours() / 24))
	case "hour":
		return fmt.Sprintf("%02d", t.Hour())
	case "minute":
		return fmt.Sprintf("%02d", t.Minute())
	case "second":
		return fmt.Sprintf("%02d", t.Second())
	case "time":
		return t.Format("15:04:05")
	case "iso8601":
		return t.Format("2006-01-02T15:04:05-07:00")
	case "std11":
		return t.Format(time.RFC1123Z)
	case "zone":
		return t.Format("-0700")
	case "weekday":
		return strconv.Itoa(int(t.Weekday()))
	}
	return ""
}

// parseZone reads a +hhmm / -hhmm zone.
func parseZone(z string) (*time.Location, error) {
	if len(z) != 5 || (z[0] != '+' && z[0] != '-') {
		return nil, fmt.Errorf("bad zone %q", z)
	}
	h, err1 := strconv.Atoi(z[1:3])
	m, err2 := strconv.Atoi(z[3:5])
	if err1 != nil || err2 != nil || h > 23 || m > 59 {
		return nil, fmt.Errorf("bad zone %q", z)
	}
	off := h*3600 + m*60
	if z[0] == '-' {
		off = -off
	}
	return time.FixedZone(z, off), nil
}

type dateTestBase struct {
	matcherTest
	Zone         string // "" for the local zone
	OriginalZone bool
	Part         string
}

func (t *dateTestBase) dateTags(s *Spec) *Spec {
	t.addSpecTags(s)
	s.Tags["zone"] = SpecTag{
		NeedsValue: true, MinStrCount: 1, MaxStrCount: 1,
		MatchStr: func(val []string) { t.Zone = val[0] },
	}
	return s
}

func (t *dateTestBase) check(d *RuntimeData, when time.Time) (bool, error) {
	if t.Zone != "" {
		loc, err := parseZone(expandVars(d, t.Zone))
		if err != nil {
			return false, nil
		}
		when = when.In(loc)
	} else if !t.OriginalZone {
		when = when.In(d.location())
	}
	value := datePart(when, strings.ToLower(t.Part))
	if t.isCount() {
		return t.countMatches(d, 1), nil
	}
	return t.tryMatch(d, value)
}

// location is the zone currentdate and date use without :zone.
func (d *RuntimeData) location() *time.Location {
	if d.Location != nil {
		return d.Location
	}
	return time.Local
}

func (d *RuntimeData) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// CurrentDateTest is RFC 5260's currentdate.
type CurrentDateTest struct{ dateTestBase }

func (t CurrentDateTest) Check(_ context.Context, d *RuntimeData) (bool, error) {
	return t.check(d, d.now())
}

// DateTest is RFC 5260's date test on a header field.
type DateTest struct {
	dateTestBase
	Header string
}

func (t DateTest) Check(_ context.Context, d *RuntimeData) (bool, error) {
	values, err := d.Msg.HeaderGet(expandVars(d, t.Header))
	if err != nil || len(values) == 0 {
		return false, nil
	}
	// RFC 5260: the last instance of the field is used.
	parsed, err := parseRFC5322Date(values[len(values)-1])
	if err != nil {
		return false, nil
	}
	return t.check(d, parsed)
}

func parseRFC5322Date(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "("); i > 0 {
		v = strings.TrimSpace(v[:i])
	}
	for _, layout := range []string{time.RFC1123Z, "Mon, 2 Jan 2006 15:04:05 -0700", "2 Jan 2006 15:04:05 -0700", time.RFC1123, "Mon, 2 Jan 2006 15:04 -0700"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable date %q", v)
}

func loadCurrentDateTest(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension("date") {
		return nil, fmt.Errorf("missing require 'date'")
	}
	loaded := CurrentDateTest{dateTestBase{matcherTest: newMatcherTest()}}
	var key []string
	err := LoadSpec(s, loaded.dateTags(&Spec{
		Pos: []SpecPosArg{
			{MinStrCount: 1, MaxStrCount: 1, MatchStr: func(val []string) { loaded.Part = val[0] }},
			{MinStrCount: 1, MatchStr: func(val []string) { key = val }},
		},
	}), test.Position, test.Args, test.Tests, nil)
	if err != nil {
		return nil, err
	}
	if !dateParts[strings.ToLower(loaded.Part)] {
		return nil, fmt.Errorf("unknown date-part %q", loaded.Part)
	}
	if err := loaded.setKey(s, key); err != nil {
		return nil, err
	}
	return loaded, nil
}

func loadDateTest(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension("date") {
		return nil, fmt.Errorf("missing require 'date'")
	}
	loaded := DateTest{dateTestBase: dateTestBase{matcherTest: newMatcherTest()}}
	var key []string
	spec := loaded.dateTags(&Spec{
		Pos: []SpecPosArg{
			{MinStrCount: 1, MaxStrCount: 1, MatchStr: func(val []string) { loaded.Header = val[0] }},
			{MinStrCount: 1, MaxStrCount: 1, MatchStr: func(val []string) { loaded.Part = val[0] }},
			{MinStrCount: 1, MatchStr: func(val []string) { key = val }},
		},
	})
	spec.Tags["originalzone"] = SpecTag{MatchBool: func() { loaded.OriginalZone = true }}
	if err := LoadSpec(s, spec, test.Position, test.Args, test.Tests, nil); err != nil {
		return nil, err
	}
	if !dateParts[strings.ToLower(loaded.Part)] {
		return nil, fmt.Errorf("unknown date-part %q", loaded.Part)
	}
	if err := loaded.setKey(s, key); err != nil {
		return nil, err
	}
	return loaded, nil
}

// ---- vacation (RFC 5230, RFC 6131) ----------------------------------------

// ActionVacation asks the delivery agent to send an automatic reply. The
// agent decides whether one is due (RFC 5230 section 4), which is outside
// the script's view: duplicate suppression, list and automated mail, and
// whether the user is a recipient.
type ActionVacation struct {
	Period    time.Duration // minimum time between replies to one sender
	Subject   string
	From      string
	Addresses []string
	Mime      bool
	Handle    string
	Reason    string
}

func (ActionVacation) testActionName() string    { return "vacation" }
func (ActionVacation) cancelsImplicitKeep() bool { return false }

// CmdVacation is the vacation command.
type CmdVacation struct {
	Days, Seconds int
	HasSeconds    bool
	Subject       string
	From          string
	Addresses     []string
	Mime          bool
	Handle        string
	Reason        string
}

func (c CmdVacation) Execute(ctx context.Context, d *RuntimeData) error {
	period := time.Duration(c.Days) * 24 * time.Hour
	if c.HasSeconds {
		period = time.Duration(c.Seconds) * time.Second
	}
	reason := expandVars(d, c.Reason)
	subject := expandVars(d, c.Subject)
	handle := expandVars(d, c.Handle)
	if handle == "" {
		// RFC 5230 section 4.2: without :handle, the reply's content
		// identifies it.
		handle = subject + "\x00" + reason + "\x00" + expandVars(d, c.From)
	}
	return d.OnAction(ctx, ActionVacation{
		Period: period, Subject: subject, From: expandVars(d, c.From), Addresses: expandVarsList(d, c.Addresses),
		Mime: c.Mime, Handle: handle, Reason: reason,
	}, d)
}

func loadVacation(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension("vacation") {
		return nil, parser.ErrorAt(pcmd.Position, "missing require 'vacation'")
	}
	cmd := CmdVacation{Days: 7}
	err := LoadSpec(s, &Spec{
		Tags: map[string]SpecTag{
			"days":      {NeedsValue: true, MatchNum: func(v int) { cmd.Days = v }},
			"seconds":   {NeedsValue: true, MatchNum: func(v int) { cmd.Seconds, cmd.HasSeconds = v, true }},
			"subject":   {NeedsValue: true, MinStrCount: 1, MaxStrCount: 1, MatchStr: func(v []string) { cmd.Subject = v[0] }},
			"from":      {NeedsValue: true, MinStrCount: 1, MaxStrCount: 1, MatchStr: func(v []string) { cmd.From = v[0] }},
			"addresses": {NeedsValue: true, MinStrCount: 1, MatchStr: func(v []string) { cmd.Addresses = v }},
			"mime":      {MatchBool: func() { cmd.Mime = true }},
			"handle":    {NeedsValue: true, MinStrCount: 1, MaxStrCount: 1, MatchStr: func(v []string) { cmd.Handle = v[0] }},
		},
		Pos: []SpecPosArg{
			{MinStrCount: 1, MaxStrCount: 1, MatchStr: func(v []string) { cmd.Reason = v[0] }},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	if err != nil {
		return nil, err
	}
	if cmd.HasSeconds && !s.RequiresExtension("vacation-seconds") {
		return nil, parser.ErrorAt(pcmd.Position, "missing require 'vacation-seconds'")
	}
	if cmd.Days < 1 {
		cmd.Days = 1 // RFC 5230: the site minimum applies; one day is ours
	}
	return cmd, nil
}
