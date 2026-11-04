package abuse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/geoip"
)

// Sign-in alerts: a successful sign-in from somewhere its account couldn't
// have reached in time, or from a country it has never signed in from. A
// stolen password works, so nothing counted as a failure notices it.
//
// They alert and never block. A phone moving between mobile networks, a VPN or
// a satellite connection all look like travel, so refusing on this would lock
// out real people; an administrator reads the alert and decides.
//
// Every service reports its sign-ins to Valkey, and the admin console alone
// places them, so only it needs the location database and its licence's
// attribution is where the results are shown.

const (
	keySignIns    = "elemta:abuse:sign-ins"
	keyLastSeen   = "elemta:abuse:seen:"
	keyCountries  = "elemta:abuse:countries:"
	keyPlaces     = "elemta:abuse:places:"
	keyAlerts     = "elemta:abuse:alerts"
	keyAlertOrder = "elemta:abuse:alerts:order"
	keyAlertOnce  = "elemta:abuse:alerts:once:"

	maxQueuedSignIns = 10000
	maxAlerts        = 500
	// signInMemory is how long where an account was is kept: long enough to
	// compare one sign-in with the last, and no longer, because it's a record
	// of where someone has been.
	signInMemory = 30 * 24 * time.Hour
	// countryMemory is how long a country stays familiar to an account.
	countryMemory = 90 * 24 * time.Hour
	// alertQuiet keeps one account flipping between two places from filling
	// the list.
	alertQuiet = time.Hour

	// travelSpeed is faster than any airliner, so a sign-in needing more is
	// two people. travelMinimum leaves out the distances a free database gets
	// wrong by guessing a neighbouring city.
	travelSpeed   = 1000.0 // km/h
	travelMinimum = 500.0  // km
	// travelMinimumDomestic applies when both places are in one country.
	// There the free database is often several hundred kilometres out:
	// mobile carriers send traffic out through a few regional gateways, so a
	// phone on cellular data is placed far from the Wi-Fi it just left. A
	// real jump that short inside one country is rarely worth an alert.
	travelMinimumDomestic = 1000.0 // km

	AlertTravel     = "impossible-travel"
	AlertNewCountry = "new-country"
)

// SignIn is one successful sign-in.
type SignIn struct {
	Time    time.Time `json:"time"`
	Account string    `json:"account"`
	Address string    `json:"address"`
	Service string    `json:"service"`
}

// seen is where an account last signed in from.
type seen struct {
	SignIn
	Place geoip.Place `json:"place"`
}

// Alert is one sign-in an administrator should look at.
type Alert struct {
	ID      string       `json:"id"`
	Time    time.Time    `json:"time"`
	Account string       `json:"account"`
	Kind    string       `json:"kind"`
	Detail  string       `json:"detail"`
	Address string       `json:"address"`
	Service string       `json:"service"`
	From    *geoip.Place `json:"from,omitempty"`
	To      geoip.Place  `json:"to"`
}

// RecordSignIn reports a successful sign-in from addr for the console to
// assess, and keeps its network as one the account uses (targeted.go). It
// costs a Valkey write or two; without Valkey the sign-in isn't assessed.
func (e *Engine) RecordSignIn(ctx context.Context, addr, service, account string) {
	if e == nil {
		return
	}
	ip := hostIP(addr)
	account = strings.ToLower(strings.TrimSpace(account))
	if ip == nil || account == "" || len(account) > 320 || ip.IsPrivate() || ip.IsLoopback() {
		return
	}
	p := e.Policy()
	if p.AddressesPerAccount > 0 && p.Mode != ModeOff {
		e.rememberNetwork(ctx, account, ip.String())
	}
	if p.SignInAlerts == "off" {
		return
	}
	client := e.valkey()
	if client == nil {
		return
	}
	raw, err := json.Marshal(SignIn{Time: time.Now().UTC(), Account: account, Address: ip.String(), Service: service})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	if client.Do(ctx, client.B().Lpush().Key(keySignIns).Element(string(raw)).Build()).Error() == nil {
		_ = client.Do(ctx, client.B().Ltrim().Key(keySignIns).Start(0).Stop(maxQueuedSignIns-1).Build()).Error()
	}
}

// Locator places an address; *geoip.DB is one.
type Locator interface {
	Locate(net.IP) (geoip.Place, bool)
}

// WatchSignIns assesses reported sign-ins until ctx ends. Only the admin
// console runs it.
func (e *Engine) WatchSignIns(ctx context.Context, places Locator) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		e.assessQueued(ctx, places)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) assessQueued(ctx context.Context, places Locator) {
	client := e.valkey()
	if client == nil {
		return
	}
	for i := 0; i < 50; i++ {
		// Its own name: assess below needs ctx, not this, which is gone.
		popCtx, cancel := context.WithTimeout(ctx, valkeyTimeout)
		// Oldest first, so the order of an account's sign-ins is kept.
		rows, err := client.Do(popCtx, client.B().Rpop().Key(keySignIns).Count(200).Build()).AsStrSlice()
		cancel()
		if err != nil || len(rows) == 0 {
			return
		}
		for _, raw := range rows {
			var s SignIn
			if json.Unmarshal([]byte(raw), &s) == nil {
				e.assess(ctx, places, s)
			}
		}
	}
}

func (e *Engine) assess(ctx context.Context, places Locator, s SignIn) {
	if e.Policy().SignInAlerts == "off" {
		return
	}
	client := e.valkey()
	if client == nil {
		return
	}
	place, ok := places.Locate(net.ParseIP(s.Address))
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*valkeyTimeout)
	defer cancel()
	var previous *seen
	if raw, err := client.Do(ctx, client.B().Get().Key(keyLastSeen+s.Account).Build()).ToString(); err == nil {
		var p seen
		if json.Unmarshal([]byte(raw), &p) == nil {
			previous = &p
		}
	}
	known, _ := client.Do(ctx, client.B().Smembers().Key(keyCountries+s.Account).Build()).AsStrSlice()
	familiar, _ := client.Do(ctx, client.B().Smembers().Key(keyPlaces+s.Account).Build()).AsStrSlice()
	for _, a := range judge(previous, s, place, known, familiar) {
		e.raise(ctx, a)
	}
	if raw, err := json.Marshal(seen{SignIn: s, Place: place}); err == nil {
		_ = client.Do(ctx, client.B().Set().Key(keyLastSeen+s.Account).Value(string(raw)).Ex(signInMemory).Build()).Error()
	}
	_ = client.Do(ctx, client.B().Sadd().Key(keyPlaces+s.Account).Member(placeKey(place)).Build()).Error()
	_ = client.Do(ctx, client.B().Expire().Key(keyPlaces+s.Account).Seconds(int64(signInMemory.Seconds())).Build()).Error()
	_ = client.Do(ctx, client.B().Sadd().Key(keyCountries+s.Account).Member(place.Country).Build()).Error()
	_ = client.Do(ctx, client.B().Expire().Key(keyCountries+s.Account).Seconds(int64(countryMemory.Seconds())).Build()).Error()
}

// judge decides what a sign-in should raise, given where the account was last,
// the countries it knows and the places it has signed in from lately. It
// touches nothing, so it can be tested alone.
//
// A sign-in from a place the account already uses isn't travel, however
// far that is from the last one: someone switching between home Wi-Fi and
// a phone on cellular data, or between a VPN and their own connection,
// flips between the same two places all day.
func judge(previous *seen, s SignIn, place geoip.Place, known, familiar []string) []Alert {
	var alerts []Alert
	if previous != nil && previous.Address != s.Address && !contains(familiar, placeKey(place)) {
		km := distance(previous.Place, place)
		elapsed := s.Time.Sub(previous.Time)
		if elapsed < time.Minute {
			elapsed = time.Minute
		}
		minimum := travelMinimum
		if previous.Place.Country != "" && previous.Place.Country == place.Country {
			minimum = travelMinimumDomestic
		}
		if km >= minimum && km/elapsed.Hours() > travelSpeed {
			from := previous.Place
			alerts = append(alerts, Alert{
				Time: s.Time, Account: s.Account, Kind: AlertTravel, Address: s.Address, Service: s.Service,
				From: &from, To: place,
				Detail: fmt.Sprintf("Signed in from %s, then from %s %s later: %s km apart, %s km/h.",
					placeName(from), placeName(place), roughDuration(s.Time.Sub(previous.Time)), thousands(km), thousands(km/elapsed.Hours())),
			})
		}
	}
	// An account with no history has nothing to be new against.
	if len(known) > 0 && !contains(known, place.Country) && len(alerts) == 0 {
		alerts = append(alerts, Alert{
			Time: s.Time, Account: s.Account, Kind: AlertNewCountry, Address: s.Address, Service: s.Service, To: place,
			Detail: fmt.Sprintf("First sign-in from %s; before this only %s.", placeName(place), strings.Join(sorted(known), ", ")),
		})
	}
	return alerts
}

func (e *Engine) raise(ctx context.Context, a Alert) {
	client := e.valkey()
	if client == nil {
		return
	}
	once := keyAlertOnce + a.Kind + ":" + a.Account
	if ok, err := client.Do(ctx, client.B().Set().Key(once).Value("1").Nx().Ex(alertQuiet).Build()).AsBool(); err == nil && !ok {
		return
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	a.ID = hex.EncodeToString(id)
	raw, err := json.Marshal(a)
	if err != nil {
		return
	}
	_ = client.Do(ctx, client.B().Hset().Key(keyAlerts).FieldValue().FieldValue(a.ID, string(raw)).Build()).Error()
	_ = client.Do(ctx, client.B().Zadd().Key(keyAlertOrder).ScoreMember().ScoreMember(float64(a.Time.UnixNano()), a.ID).Build()).Error()
	// Keep the newest; the oldest leave both the order and the alerts.
	if old, err := client.Do(ctx, client.B().Zrange().Key(keyAlertOrder).Min("0").Max(fmt.Sprint(-maxAlerts-1)).Build()).AsStrSlice(); err == nil && len(old) > 0 {
		_ = client.Do(ctx, client.B().Hdel().Key(keyAlerts).Field(old...).Build()).Error()
		_ = client.Do(ctx, client.B().Zrem().Key(keyAlertOrder).Member(old...).Build()).Error()
	}
	metricAlerts.WithLabelValues(a.Kind).Inc()
	subject, body := alertSubjectBody(a)
	e.notify(ctx, subject, body)
	e.record(ctx, Event{Action: a.Kind, Network: a.Address, Service: a.Service, Detail: a.Account + ": " + a.Detail})
	e.log.Warn("Sign-in alert", "kind", a.Kind, "account", a.Account, "address", a.Address, "detail", a.Detail)
}

// Alerts lists sign-in alerts, newest first.
func (e *Engine) Alerts(ctx context.Context) []Alert {
	out := []Alert{}
	client := e.valkey()
	if e == nil || client == nil {
		return out
	}
	rows, err := client.Do(ctx, client.B().Hvals().Key(keyAlerts).Build()).AsStrSlice()
	if err != nil {
		return out
	}
	for _, raw := range rows {
		var a Alert
		if json.Unmarshal([]byte(raw), &a) == nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// DismissAlert removes an alert an administrator has dealt with.
func (e *Engine) DismissAlert(ctx context.Context, id, by string) error {
	client := e.valkey()
	if client == nil {
		return fmt.Errorf("alerts need Valkey, which is unreachable")
	}
	if id == "" || len(id) > 64 {
		return fmt.Errorf("name the alert to dismiss")
	}
	if err := client.Do(ctx, client.B().Hdel().Key(keyAlerts).Field(id).Build()).Error(); err != nil {
		return err
	}
	_ = client.Do(ctx, client.B().Zrem().Key(keyAlertOrder).Member(id).Build()).Error()
	e.log.Info("Sign-in alert dismissed", "id", id, "by", by)
	return nil
}

// distance is the great-circle distance in kilometres.
// placeKey names a place for the account's familiar places: the city where
// the database has one, or else the coordinates to about 10 km.
func placeKey(p geoip.Place) string {
	if p.City != "" {
		return strings.ToLower(p.Country + "/" + p.City)
	}
	return fmt.Sprintf("%s/%.1f,%.1f", strings.ToLower(p.Country), p.Latitude, p.Longitude)
}

func distance(a, b geoip.Place) float64 {
	const earth = 6371.0
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat, dLon := rad(b.Latitude-a.Latitude), rad(b.Longitude-a.Longitude)
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(rad(a.Latitude))*math.Cos(rad(b.Latitude))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earth * math.Asin(math.Min(1, math.Sqrt(h)))
}

func placeName(p geoip.Place) string {
	if p.City != "" {
		return p.City + ", " + p.Country
	}
	return p.Country
}

func roughDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
}

func thousands(f float64) string {
	s := fmt.Sprintf("%d", int64(math.Round(f)))
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sorted(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}
