package webmail

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	holidaydata "github.com/holidays/go-holidays"
)

const holidayCalendar = "Holidays"

//go:embed holiday_zones.tab
var holidayZonesText string

type holidayRegionChoice struct {
	Code, Label string
}

type hiddenHolidayChoice struct {
	Key, Label string
}

func holidayCountryForZone(zone string) string {
	for _, line := range strings.Split(holidayZonesText, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == zone {
			country := strings.ToLower(fields[0])
			if validHolidayCountry(country) {
				return country
			}
			break
		}
	}
	return "us"
}

func inferredHolidayRegion(preferred, fallback string) string {
	if preferred != "" {
		return holidayCountryForZone(preferred)
	}
	return holidayCountryForZone(fallback)
}

func holidayRegionLabel(code string) string {
	if name, ok := holidaydata.RegionName(code); ok {
		return name
	}
	return strings.ToUpper(code)
}

func holidayRegionChoices(countriesOnly bool) []holidayRegionChoice {
	names := holidaydata.RegionNames()
	var choices []holidayRegionChoice
	for _, code := range holidaydata.AvailableRegions() {
		if len(code) < 2 || len(code) > 16 || code[0] < 'a' || code[0] > 'z' || code[1] < 'a' || code[1] > 'z' || len(code) > 2 && code[2] != '_' {
			continue
		}
		if countriesOnly && len(code) != 2 {
			continue
		}
		name := names[code]
		if name == "" {
			name = strings.ToUpper(code)
		}
		label := name + " (" + strings.ToUpper(code) + ")"
		if len(code) > 2 {
			if country := names[code[:2]]; country != "" {
				label = country + " — " + label
			}
		}
		choices = append(choices, holidayRegionChoice{Code: code, Label: label})
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].Label < choices[j].Label })
	return choices
}

func validHolidayRegion(region string) bool {
	for _, choice := range holidayRegionChoices(false) {
		if choice.Code == region {
			return true
		}
	}
	return false
}

func validHolidayCountry(country string) bool {
	for _, choice := range holidayRegionChoices(true) {
		if choice.Code == country {
			return true
		}
	}
	return false
}

func (p Settings) holidayRegions(fallbackZone string) []string {
	region := p.HolidayRegion
	if region == "" || !validHolidayRegion(region) {
		region = inferredHolidayRegion(p.Timezone, fallbackZone)
	}
	regions := []string{region}
	for _, country := range p.HolidayExtraCountries {
		if validHolidayCountry(country) && country != region && !strings.HasPrefix(region, country+"_") && !slices.Contains(regions, country) {
			regions = append(regions, country)
		}
	}
	return regions
}

func holidayKey(region, name string) string { return region + "|" + name }

func hiddenHolidayChoices(keys []string) []hiddenHolidayChoice {
	var choices []hiddenHolidayChoice
	for _, key := range keys {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 || !validHolidayRegion(parts[0]) {
			continue
		}
		region, ok := holidaydata.RegionName(parts[0])
		if !ok {
			region = strings.ToUpper(parts[0])
		}
		choices = append(choices, hiddenHolidayChoice{Key: key, Label: parts[1] + " · " + region})
	}
	return choices
}

// holidayEvents builds just the visible date window. The source defines dates
// without a time zone, so they are placed at midnight in the user's zone.
func holidayEvents(p Settings, fallbackZone string, loc *time.Location, from, to time.Time) ([]Event, error) {
	if p.HolidayDisabled {
		return nil, nil
	}
	var events []Event
	for _, region := range p.holidayRegions(fallbackZone) {
		name, _ := holidaydata.RegionName(region)
		start := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
		endDay := to.AddDate(0, 0, -1)
		end := time.Date(endDay.Year(), endDay.Month(), endDay.Day(), 0, 0, 0, 0, time.UTC)
		hs, err := holidaydata.Between(start, end, holidaydata.Options{Regions: []string{region}, Informal: p.HolidayInformal, Observed: p.HolidayObserved})
		if err != nil {
			return nil, err
		}
		for _, h := range hs {
			key := holidayKey(region, h.Name)
			if slices.Contains(p.HolidayHidden, key) {
				continue
			}
			d := time.Date(h.Date.Year(), h.Date.Month(), h.Date.Day(), 0, 0, 0, 0, loc)
			sum := sha256.Sum256([]byte(key))
			uid := fmt.Sprintf("holiday-%s-%s-%s", region, d.Format("20060102"), hex.EncodeToString(sum[:8]))
			description := "Holiday in " + name + "."
			if h.Informal {
				description = "Informal holiday in " + name + "."
			}
			events = append(events, Event{UID: uid, Summary: h.Name, Description: description, Calendar: holidayCalendar,
				Start: d, End: d.AddDate(0, 0, 1), AllDay: true, Reminder: -1, ReadOnly: true, HolidayKey: key})
		}
	}
	return events, nil
}

func (s *Server) holidayHide(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	p := s.prefs(r.Context(), sess)
	day, err := time.ParseInLocation("2006-01-02", r.PostFormValue("date"), loc)
	if err != nil {
		http.Error(w, "invalid holiday date", http.StatusBadRequest)
		return
	}
	visible, err := holidayEvents(p, s.defaultLoc.String(), loc, day, day.AddDate(0, 0, 1))
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	for _, e := range visible {
		if e.UID == r.PostFormValue("uid") {
			if len(p.HolidayHidden) >= 100 {
				http.Error(w, "too many hidden holidays", http.StatusBadRequest)
				return
			}
			p.HolidayHidden = append(p.HolidayHidden, e.HolidayKey)
			if err := s.savePrefs(r.Context(), sess, p); err != nil {
				s.fail(w, r, sess, err)
				return
			}
			redirectLocal(w, r, localBack(r.PostFormValue("back"), calURL("month", day)))
			return
		}
	}
	http.Error(w, "holiday not found", http.StatusNotFound)
}
