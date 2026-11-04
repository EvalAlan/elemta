package abuse

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/geoip"
)

var (
	paris  = geoip.Place{Country: "FR", City: "Paris", Latitude: 48.8566, Longitude: 2.3522}
	lyon   = geoip.Place{Country: "FR", City: "Lyon", Latitude: 45.764, Longitude: 4.8357}
	sydney = geoip.Place{Country: "AU", City: "Sydney", Latitude: -33.8688, Longitude: 151.2093}
	berlin = geoip.Place{Country: "DE", City: "Berlin", Latitude: 52.52, Longitude: 13.405}
)

func at(minutes int) time.Time {
	return time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC).Add(time.Duration(minutes) * time.Minute)
}

func was(place geoip.Place, address string, minutes int) *seen {
	return &seen{SignIn: SignIn{Time: at(minutes), Account: "dana@example.com", Address: address}, Place: place}
}

func now(address string, minutes int) SignIn {
	return SignIn{Time: at(minutes), Account: "dana@example.com", Address: address, Service: "imap"}
}

func kinds(alerts []Alert) string {
	var out []string
	for _, a := range alerts {
		out = append(out, a.Kind)
	}
	return strings.Join(out, ",")
}

func TestJudgeSignIns(t *testing.T) {
	for _, c := range []struct {
		name     string
		previous *seen
		signIn   SignIn
		place    geoip.Place
		known    []string
		want     string
	}{
		{"Paris then Sydney in 20 minutes", was(paris, "1.1.1.1", 0), now("2.2.2.2", 20), sydney, []string{"FR"}, AlertTravel},
		{"Paris then Sydney a day later is a flight", was(paris, "1.1.1.1", 0), now("2.2.2.2", 24*60), sydney, []string{"FR"}, AlertNewCountry},
		{"Paris then Lyon by train", was(paris, "1.1.1.1", 0), now("2.2.2.2", 120), lyon, []string{"FR"}, ""},
		// The database guesses a city per range; near ones disagree for the
		// same person, so short distances never count as travel.
		{"Paris then Lyon in a minute is a database guess", was(paris, "1.1.1.1", 0), now("2.2.2.2", 1), lyon, []string{"FR"}, ""},
		{"same address, wherever the database puts it", was(paris, "1.1.1.1", 0), now("1.1.1.1", 1), sydney, []string{"FR", "AU"}, ""},
		{"first sign-in ever", nil, now("1.1.1.1", 0), berlin, nil, ""},
		{"a known country", was(paris, "1.1.1.1", 0), now("2.2.2.2", 3000), berlin, []string{"FR", "DE"}, ""},
		{"a new country, reachable", was(paris, "1.1.1.1", 0), now("2.2.2.2", 3000), berlin, []string{"FR"}, AlertNewCountry},
	} {
		got := judge(c.previous, c.signIn, c.place, c.known, nil)
		if kinds(got) != c.want {
			t.Errorf("%s: got %q, want %q", c.name, kinds(got), c.want)
		}
	}
	got := judge(was(paris, "1.1.1.1", 0), now("2.2.2.2", 20), sydney, []string{"FR"}, nil)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "Paris, FR") || !strings.Contains(got[0].Detail, "Sydney, AU") || !strings.Contains(got[0].Detail, "20 minutes") {
		t.Fatalf("detail = %+v", got)
	}
}

// The false positive that prompted this: a phone on cellular data placed
// several hundred kilometres from the home Wi-Fi it alternates with, within
// a minute.
func TestJudgeHomeAndPhone(t *testing.T) {
	boston := geoip.Place{Country: "US", City: "Boston", Latitude: 42.3601, Longitude: -71.0589}
	buffalo := geoip.Place{Country: "US", City: "Buffalo", Latitude: 42.8864, Longitude: -78.8784}
	if km := distance(boston, buffalo); km < 600 || km > 700 {
		t.Fatalf("fixture distance %.0f km", km)
	}
	// Under the domestic minimum: no alert even the first time.
	if got := judge(was(boston, "198.51.100.7", 0), now("203.0.113.9", 0), buffalo, []string{"US"}, nil); len(got) != 0 {
		t.Fatalf("home then phone raised %s", kinds(got))
	}
	// The same jump across a border still counts.
	toronto := geoip.Place{Country: "CA", City: "Toronto", Latitude: 43.6532, Longitude: -79.3832}
	if got := judge(was(boston, "198.51.100.7", 0), now("203.0.113.9", 1), toronto, []string{"US", "CA"}, nil); kinds(got) != AlertTravel {
		t.Fatalf("cross-border jump raised %q", kinds(got))
	}
}

// A place the account signed in from lately isn't travel: a VPN exit and
// home, flipping all day, alert once at most.
func TestJudgeFamiliarPlaces(t *testing.T) {
	if got := judge(was(paris, "1.1.1.1", 0), now("2.2.2.2", 20), sydney, []string{"FR", "AU"}, []string{placeKey(paris), placeKey(sydney)}); len(got) != 0 {
		t.Fatalf("familiar place raised %s", kinds(got))
	}
	// An unfamiliar destination still does, even with other places known.
	if got := judge(was(paris, "1.1.1.1", 0), now("2.2.2.2", 20), sydney, []string{"FR"}, []string{placeKey(paris), placeKey(berlin)}); kinds(got) != AlertTravel {
		t.Fatalf("unfamiliar place raised %q", kinds(got))
	}
	if placeKey(geoip.Place{Country: "US", Latitude: 40.71, Longitude: -74.0}) != "us/40.7,-74.0" || placeKey(paris) != "fr/paris" {
		t.Fatalf("placeKey: %q %q", placeKey(geoip.Place{Country: "US", Latitude: 40.71, Longitude: -74.0}), placeKey(paris))
	}
}

func TestDistance(t *testing.T) {
	if km := distance(paris, sydney); km < 16900 || km > 17000 {
		t.Fatalf("Paris to Sydney = %.0f km", km)
	}
	if km := distance(paris, paris); km != 0 {
		t.Fatalf("Paris to itself = %.0f km", km)
	}
}

func TestPrivateSignInsAreNotRecorded(t *testing.T) {
	e := testEngine(t, DefaultPolicy())
	// No Valkey, so nothing could be recorded anyway; this checks it doesn't panic.
	e.RecordSignIn(context.Background(), "10.0.0.5:1234", "imap", "dana@example.com")
	var nilEngine *Engine
	nilEngine.RecordSignIn(context.Background(), "1.1.1.1", "imap", "dana@example.com")
}

type fixedPlaces map[string]geoip.Place

func (f fixedPlaces) Locate(ip net.IP) (geoip.Place, bool) {
	p, ok := f[ip.String()]
	return p, ok
}

// The whole path: services report, the console assesses and raises once, and
// an administrator dismisses. Set ELEMTA_TEST_VALKEY_ADDR.
func TestSignInAlertsThroughValkey(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("ELEMTA_TEST_VALKEY_ADDR not set")
	}
	ctx := context.Background()
	mailbox, console := New("mailbox", addr, nil), New("admin", addr, nil)
	for _, e := range []*Engine{mailbox, console} {
		if err := e.Publish(ctx, DefaultPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	account := fmt.Sprintf("travel-%d@example.com", time.Now().UnixNano())
	places := fixedPlaces{"192.0.2.1": paris, "198.51.100.1": sydney, "203.0.113.1": sydney}
	mailbox.RecordSignIn(ctx, "192.0.2.1:5000", "imap", account)
	mailbox.RecordSignIn(ctx, "198.51.100.1:5000", "pop3", account)
	mailbox.RecordSignIn(ctx, "203.0.113.1:5000", "imap", account) // the same trip again
	console.assessQueued(ctx, places)

	var mine []Alert
	for _, a := range console.Alerts(ctx) {
		if a.Account == account {
			mine = append(mine, a)
		}
	}
	if len(mine) != 1 || mine[0].Kind != AlertTravel || mine[0].Service != "pop3" {
		t.Fatalf("alerts = %+v", mine)
	}
	if err := console.DismissAlert(ctx, mine[0].ID, "test"); err != nil {
		t.Fatal(err)
	}
	for _, a := range console.Alerts(ctx) {
		if a.ID == mine[0].ID {
			t.Fatal("dismissed alert still listed")
		}
	}
}

// With the real database, if it's here. Set ELEMTA_TEST_GEOIP_DB.
func TestRealDatabasePlacesAddresses(t *testing.T) {
	path := os.Getenv("ELEMTA_TEST_GEOIP_DB")
	if path == "" {
		t.Skip("ELEMTA_TEST_GEOIP_DB not set")
	}
	db, err := geoip.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for ip, country := range map[string]string{"8.8.8.8": "US", "1.1.1.1": "AU", "2001:4860:4860::8888": "US"} {
		p, ok := db.Locate(net.ParseIP(ip))
		if !ok || p.Country == "" || p.Latitude == 0 {
			t.Errorf("%s: %+v, %v", ip, p, ok)
		}
		t.Logf("%s -> %+v (expected about %s)", ip, p, country)
	}
	if _, ok := db.Locate(net.ParseIP("10.1.2.3")); ok {
		t.Error("a private address was placed")
	}
}
