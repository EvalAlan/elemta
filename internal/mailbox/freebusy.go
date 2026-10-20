package mailbox

// Free/busy. The calendars themselves are the webmail's objects (in IMAP
// folders or its own Postgres store), which only the webmail can read and
// expand, recurrences and all. So the webmail publishes each account's busy
// times here whenever its calendar changes, and colleagues in the same
// domain read them: only start, end and tentative, never titles.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// BusyBlock is a time the account is busy, in UTC.
type BusyBlock struct {
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Tentative bool      `json:"tentative,omitempty"`
}

// FreeBusy is what an account published, or for a lookup, what was found.
type FreeBusy struct {
	Address string      `json:"address"`
	Known   bool        `json:"known"` // false: not in your domain, or never published
	From    time.Time   `json:"from,omitzero"`
	To      time.Time   `json:"to,omitzero"`
	Updated time.Time   `json:"updated,omitzero"`
	Busy    []BusyBlock `json:"busy"`
}

const (
	maxBusyBlocks  = 5000
	maxBusyWindow  = 400 * 24 * time.Hour
	maxBusyLookups = 50
)

var errBadFreeBusy = &requestError{"invalid free/busy"}

// PublishFreeBusy replaces an account's published busy times.
func (e *Engine) PublishFreeBusy(ctx context.Context, account Account, fb FreeBusy) error {
	if fb.From.IsZero() || !fb.To.After(fb.From) || fb.To.Sub(fb.From) > maxBusyWindow || len(fb.Busy) > maxBusyBlocks {
		return errBadFreeBusy
	}
	for _, b := range fb.Busy {
		if !b.End.After(b.Start) {
			return errBadFreeBusy
		}
	}
	data, err := json.Marshal(fb.Busy)
	if err != nil {
		return err
	}
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_freebusy(account,address,window_from,window_to,busy,updated) VALUES($1,$2,$3,$4,$5,now())
ON CONFLICT (account) DO UPDATE SET address=EXCLUDED.address, window_from=EXCLUDED.window_from, window_to=EXCLUDED.window_to, busy=EXCLUDED.busy, updated=now()`,
		account.ID, strings.ToLower(account.Address), fb.From.UTC(), fb.To.UTC(), data)
	return err
}

// freeBusy looks up colleagues' busy times between from and to for viewer.
// Addresses outside the viewer's domain come back unknown, exactly like an
// address that never published, so the answer doesn't reveal who exists
// elsewhere.
func (s *Service) freeBusy(ctx context.Context, viewer Account, addresses []string, from, to time.Time) ([]FreeBusy, error) {
	if len(addresses) > maxBusyLookups || !to.After(from) || to.Sub(from) > maxBusyWindow {
		return nil, errBadFreeBusy
	}
	domain := viewer.Address[strings.LastIndexByte(viewer.Address, '@')+1:]
	out := make([]FreeBusy, 0, len(addresses))
	for _, raw := range addresses {
		address := strings.ToLower(strings.TrimSpace(raw))
		fb := FreeBusy{Address: address, Busy: []BusyBlock{}}
		if !strings.HasSuffix(address, "@"+domain) {
			out = append(out, fb)
			continue
		}
		var data []byte
		err := s.engine.DB.QueryRowContext(ctx, `SELECT window_from, window_to, updated, busy FROM mailbox_freebusy WHERE address=$1`, address).Scan(&fb.From, &fb.To, &fb.Updated, &data)
		if errors.Is(err, sql.ErrNoRows) {
			// An alias: published under the account's own address.
			if a, rerr := s.auth.Resolve(ctx, address); rerr == nil && a.Address != address {
				err = s.engine.DB.QueryRowContext(ctx, `SELECT window_from, window_to, updated, busy FROM mailbox_freebusy WHERE account=$1`, a.ID).Scan(&fb.From, &fb.To, &fb.Updated, &data)
			}
		}
		if errors.Is(err, sql.ErrNoRows) {
			out = append(out, fb)
			continue
		}
		if err != nil {
			return nil, err
		}
		var all []BusyBlock
		if err := json.Unmarshal(data, &all); err != nil {
			return nil, err
		}
		fb.Known = true
		for _, b := range all {
			if b.Start.Before(to) && b.End.After(from) {
				fb.Busy = append(fb.Busy, b)
			}
		}
		out = append(out, fb)
	}
	return out, nil
}
