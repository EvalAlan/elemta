package webmail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAwayBanner(t *testing.T) {
	now := time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		v    Vacation
		want *awayView
	}{
		{"off", Vacation{Start: "2026-12-01"}, nil},
		{"on, no dates", Vacation{Enabled: true}, &awayView{}},
		{"on until", Vacation{Enabled: true, Start: "2026-12-01", End: "2026-12-03"}, &awayView{Until: "Thu 3 Dec"}},
		{"last day", Vacation{Enabled: true, End: "2026-12-02"}, &awayView{Until: "Wed 2 Dec"}},
		{"over", Vacation{Enabled: true, End: "2026-12-01"}, nil},
		{"not yet", Vacation{Enabled: true, Start: "2026-12-05", End: "2026-12-09"}, &awayView{Starts: "Sat 5 Dec", Until: "Wed 9 Dec"}},
	} {
		got := awayBanner(tc.v, now, time.UTC)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// The day is the user's: 02:00 UTC on the 4th is still the 3rd in New York.
	ny, _ := time.LoadLocation("America/New_York")
	late := time.Date(2026, 12, 4, 2, 0, 0, 0, time.UTC)
	if awayBanner(Vacation{Enabled: true, End: "2026-12-03"}, late, ny) == nil {
		t.Error("reply ended early for a user west of UTC")
	}
}

func TestOutOfOfficePageAndBanner(t *testing.T) {
	h := newHarness(t)
	fs := &fakeSieve{scripts: map[string]string{}}
	h.server.sieve = func(context.Context, string, string) (SieveConn, error) { return fs, nil }
	csrf := h.login()

	_, body := h.get("/mail")
	if strings.Contains(body, "data-away") {
		t.Fatal("banner shown with no reply set")
	}
	_, body = h.get("/settings/out-of-office")
	for _, want := range []string{"<h1>Out of office</h1>", `name="op" value="vacation"`, `href="/settings/out-of-office" aria-current="page"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}

	end := time.Now().AddDate(0, 0, 3).Format("2006-01-02")
	resp := h.post("/filters", url.Values{"csrf": {csrf}, "op": {"vacation"}, "enabled": {"1"}, "body": {"Away"}, "days": {"1"}, "end": {end}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/settings/out-of-office?") {
		t.Fatalf("save = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = h.get("/mail")
	if !strings.Contains(body, "data-away") || !strings.Contains(body, "Automatic replies are on until "+friendlyDay(end)) {
		t.Fatalf("banner missing after turning the reply on:\n%s", body)
	}
	// Its own page doesn't repeat it.
	if _, body = h.get("/settings/out-of-office"); strings.Contains(body, "data-away") {
		t.Error("banner shown on the out-of-office page")
	}

	resp = h.post("/filters", url.Values{"csrf": {csrf}, "op": {"vacation-off"}, "back": {"/mail?f=INBOX"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=vacation-off") {
		t.Fatalf("turn off = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	set, _ := parseFilterScript(fs.scripts[sieveScriptName])
	if set.Vacation.Enabled || set.Vacation.Body != "Away" {
		t.Fatalf("after turning off: %+v (the message should be kept)", set.Vacation)
	}
	if _, body = h.get("/mail"); strings.Contains(body, "data-away") {
		t.Error("banner still shown after Turn off")
	}
}

// A reply set from another device shows up once the session reads it.
func TestAwayBannerReadsTheServer(t *testing.T) {
	h := newHarness(t)
	set := FilterSet{Vacation: Vacation{Enabled: true, Body: "Away", Days: 1}}
	script, err := generateSieve(set)
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeSieve{scripts: map[string]string{sieveScriptName: script}, active: sieveScriptName}
	h.server.sieve = func(context.Context, string, string) (SieveConn, error) { return fs, nil }
	h.login()
	if _, body := h.get("/mail"); !strings.Contains(body, "Automatic replies are on.") {
		t.Fatalf("banner missing for a reply already on the server:\n%s", body)
	}
}
