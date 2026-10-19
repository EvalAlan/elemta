package webmail

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHolidayRegionAndPreferences(t *testing.T) {
	for zone, want := range map[string]string{
		"America/New_York": "us",
		"Europe/Paris":     "fr",
		"Asia/Tokyo":       "jp",
		"Australia/Sydney": "au",
	} {
		if got := holidayCountryForZone(zone); got != want {
			t.Errorf("%s: got %s, want %s", zone, got, want)
		}
	}
	loc, _ := time.LoadLocation("Europe/Paris")
	day := time.Date(2026, 7, 14, 0, 0, 0, 0, loc)
	p := Settings{Timezone: "Europe/Paris"}
	events, err := holidayEvents(p, "UTC", loc, day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || !strings.Contains(strings.ToLower(events[0].Summary), "fête nationale") {
		t.Fatalf("Paris holidays on July 14: %+v", events)
	}
	if !events[0].AllDay || !events[0].ReadOnly || events[0].Start.Location() != loc {
		t.Fatalf("holiday is not a local read-only all-day event: %+v", events[0])
	}
	p.HolidayHidden = []string{events[0].HolidayKey}
	if hidden, err := holidayEvents(p, "UTC", loc, day, day.AddDate(0, 0, 1)); err != nil || len(hidden) != 0 {
		t.Fatalf("hidden holiday: %+v, %v", hidden, err)
	}
	p.HolidayDisabled = true
	if disabled, err := holidayEvents(p, "UTC", loc, day, day.AddDate(0, 0, 1)); err != nil || len(disabled) != 0 {
		t.Fatalf("disabled holidays: %+v, %v", disabled, err)
	}
	p = Settings{HolidayRegion: "us_ca", HolidayExtraCountries: []string{"us", "fr"}}
	if got := p.holidayRegions("UTC"); len(got) != 2 || got[0] != "us_ca" || got[1] != "fr" {
		t.Fatalf("selected regions: %v", got)
	}
}

func TestHolidayCalendarSettingsAndHide(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	day := "2026-07-04"
	_, page := h.get("/calendar?view=day&date=" + day)
	if !strings.Contains(page, "Independence Day") {
		t.Fatal("US holiday should be visible by default")
	}
	if !strings.Contains(page, "Customize holidays") {
		t.Fatal("calendar has no holiday settings link")
	}
	loc := h.server.defaultLoc
	d, _ := time.ParseInLocation("2006-01-02", day, loc)
	events, err := holidayEvents(Settings{}, loc.String(), loc, d, d.AddDate(0, 0, 1))
	if err != nil || len(events) == 0 {
		t.Fatalf("holiday lookup: %+v, %v", events, err)
	}
	_, detail := h.get(eventURL(events[0].UID, events[0].Start))
	if !strings.Contains(detail, "Hide this holiday") || strings.Contains(detail, "Delete series") || strings.Contains(detail, "Edit</a>") {
		t.Fatal("holiday detail should offer hide, without event edit actions")
	}
	resp := h.post("/calendar/holiday/hide", url.Values{"csrf": {csrf}, "date": {day}, "uid": {events[0].UID}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("hide status: %d", resp.StatusCode)
	}
	_, page = h.get("/calendar?view=day&date=" + day)
	if strings.Contains(page, "Independence Day") {
		t.Fatal("hidden holiday still visible")
	}
	_, settings := h.get("/settings")
	if !strings.Contains(settings, "Show Independence Day") {
		t.Fatal("hidden holiday cannot be restored")
	}
	resp = h.post("/settings", url.Values{"csrf": {csrf}, "holiday_enabled": {"1"}, "holiday_restore": {events[0].HolidayKey}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("restore status: %d", resp.StatusCode)
	}
	_, page = h.get("/calendar?view=day&date=" + day)
	if !strings.Contains(page, "Independence Day") {
		t.Fatal("restored holiday missing")
	}
	resp = h.post("/settings", url.Values{"csrf": {csrf}, "holiday_region": {"fr"}, "holiday_enabled": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("country status: %d", resp.StatusCode)
	}
	_, page = h.get("/calendar?view=day&date=" + day)
	if strings.Contains(page, "Independence Day") {
		t.Fatal("US holiday visible after choosing France")
	}
	resp = h.post("/settings", url.Values{"csrf": {csrf}, "holiday_region": {"us"}, "holiday_extra_countries": {"fr"}, "holiday_enabled": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("additional country status: %d", resp.StatusCode)
	}
	_, page = h.get("/calendar?view=day&date=" + day)
	if !strings.Contains(page, "Independence Day") {
		t.Fatal("primary country missing with an additional country")
	}
	_, page = h.get("/calendar?view=day&date=2026-07-14")
	if !strings.Contains(page, "Fête nationale") {
		t.Fatal("additional country holiday missing")
	}
	resp = h.post("/settings", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("disable status: %d", resp.StatusCode)
	}
	_, page = h.get("/calendar?view=day&date=" + day)
	if strings.Contains(page, "Independence Day") {
		t.Fatal("holiday visible after disabling")
	}
}

// A holiday several of the user's regions share is one event, naming each
// region, and hiding it hides it everywhere it was merged from.
func TestHolidaysSharedAcrossRegionsShownOnce(t *testing.T) {
	loc := time.UTC
	p := Settings{HolidayRegion: "us", HolidayExtraCountries: []string{"gb"}}
	day := time.Date(2026, 12, 25, 0, 0, 0, 0, loc)
	events, err := holidayEvents(p, "UTC", loc, day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	var christmas []Event
	for _, e := range events {
		if holidayNameKey(e.Summary) == "christmasday" {
			christmas = append(christmas, e)
		}
	}
	if len(christmas) != 1 {
		t.Fatalf("Christmas Day shown %d times: %+v", len(christmas), events)
	}
	c := christmas[0]
	if len(c.HolidayKeys) != 2 || !strings.Contains(c.Description, "United States") || !strings.Contains(c.Description, " and ") {
		t.Fatalf("merged holiday = %q keys %v", c.Description, c.HolidayKeys)
	}
	// Boxing Day is the UK's alone and stays its own event.
	boxing, err := holidayEvents(p, "UTC", loc, day.AddDate(0, 0, 1), day.AddDate(0, 0, 2))
	if err != nil || len(boxing) != 1 || len(boxing[0].HolidayKeys) != 1 {
		t.Fatalf("Boxing Day: %+v, %v", boxing, err)
	}
	p.HolidayHidden = c.HolidayKeys
	if left, _ := holidayEvents(p, "UTC", loc, day, day.AddDate(0, 0, 1)); len(left) != len(events)-1 {
		t.Fatalf("after hiding the merged holiday: %+v", left)
	}
	if holidayNameKey("New Year's Day") != holidayNameKey("New Years  day") {
		t.Error("names differing only in punctuation and case should match")
	}
}
