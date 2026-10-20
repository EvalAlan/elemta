package mailbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFreeBusy(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_freebusy WHERE account LIKE 'fb-%' OR account=$1`, a.ID) })
	domain := a.Address[strings.LastIndexByte(a.Address, '@')+1:]
	lee := Account{ID: "fb-lee", Address: "fb-lee@" + domain}
	other := Account{ID: "fb-other", Address: "fb-mallory@elsewhere.example"}
	day := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	window := FreeBusy{From: day.AddDate(0, 0, -1), To: day.AddDate(0, 6, 0)}
	busy := func(h1, h2 int) BusyBlock {
		return BusyBlock{Start: day.Add(time.Duration(h1) * time.Hour), End: day.Add(time.Duration(h2) * time.Hour)}
	}

	fb := window
	fb.Busy = []BusyBlock{busy(9, 10), busy(30, 31)}
	if err := e.PublishFreeBusy(ctx, lee, fb); err != nil {
		t.Fatal(err)
	}
	fb.Busy = []BusyBlock{busy(9, 17)}
	if err := e.PublishFreeBusy(ctx, other, fb); err != nil {
		t.Fatal(err)
	}
	// Publishing again replaces.
	fb.Busy = []BusyBlock{busy(11, 12), busy(30, 31)}
	if err := e.PublishFreeBusy(ctx, lee, fb); err != nil {
		t.Fatal(err)
	}
	bad := window
	bad.Busy = []BusyBlock{busy(12, 11)}
	var re *requestError
	if err := e.PublishFreeBusy(ctx, lee, bad); !errors.As(err, &re) {
		t.Errorf("an inverted block was accepted: %v", err)
	}

	s := &Service{engine: e, auth: testAuth{a}}
	got, err := s.freeBusy(ctx, a, []string{"FB-LEE@" + domain, other.Address, "nobody@" + domain}, day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if !got[0].Known || len(got[0].Busy) != 1 || !got[0].Busy[0].Start.Equal(day.Add(11*time.Hour)) {
		t.Errorf("lee, clipped to the day = %+v", got[0])
	}
	if got[1].Known || len(got[1].Busy) != 0 {
		t.Errorf("another domain's busy times were shown: %+v", got[1])
	}
	if got[2].Known {
		t.Errorf("someone who never published = %+v", got[2])
	}
	if _, err := s.freeBusy(ctx, a, make([]string, maxBusyLookups+1), day, day.AddDate(0, 0, 1)); err == nil {
		t.Error("too many lookups at once were accepted")
	}
}
