package mailbox

// Rooms and other bookable resources. A resource is an ordinary account with a
// row here, so it receives mail, has a calendar and publishes free/busy like
// anyone, and it can be shared with a delegate like anyone. Nobody signs in to
// it, so invitations are answered at delivery.
//
// Automatic booking is first come, first served. Approval needs nothing of its
// own: an invitation to a manual resource lands in its inbox, goes to its
// delegates like anyone's (itip.go), and whoever is delegate answers for it.
//
// Only a colleague can book. An outside address can reach a room like any other
// mailbox, and if that took a slot, or drew a reply, anyone could fill a room's
// calendar or use it to send mail to a forged address. Such an invitation
// stays in the inbox unanswered.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/webmail"
)

// PutResource makes an account bookable, or changes how it books.
func (e *Engine) PutResource(ctx context.Context, account Account, r mailpolicy.Resource) (mailpolicy.Resource, error) {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > 200 {
		return r, errors.Join(mailpolicy.ErrInvalid, errors.New("give the resource a name"))
	}
	if r.Kind == "" {
		r.Kind = mailpolicy.ResourceRoom
	}
	if r.Kind != mailpolicy.ResourceRoom && r.Kind != mailpolicy.ResourceEquipment {
		return r, errors.Join(mailpolicy.ErrInvalid, errors.New("kind must be room or equipment"))
	}
	if r.Booking == "" {
		r.Booking = mailpolicy.BookingAuto
	}
	if r.Booking != mailpolicy.BookingAuto && r.Booking != mailpolicy.BookingManual {
		return r, errors.Join(mailpolicy.ErrInvalid, errors.New("booking must be auto or manual"))
	}
	if r.Capacity < 0 || len(r.Location) > 200 {
		return r, errors.Join(mailpolicy.ErrInvalid, errors.New("check the capacity and location"))
	}
	if err := e.EnsureAccount(ctx, account); err != nil {
		return r, err
	}
	r.Address = strings.ToLower(account.Address)
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_resources(account,address,name,kind,location,capacity,booking) VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(account) DO UPDATE SET address=EXCLUDED.address,name=EXCLUDED.name,kind=EXCLUDED.kind,location=EXCLUDED.location,capacity=EXCLUDED.capacity,booking=EXCLUDED.booking`,
		account.ID, r.Address, r.Name, r.Kind, r.Location, r.Capacity, r.Booking)
	return r, err
}

// DeleteResource makes an account an ordinary one again. Its calendar stays.
func (e *Engine) DeleteResource(ctx context.Context, account string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_resources WHERE account=$1`, account)
	return err
}

// Resource returns an account's resource settings, nil for a person.
func (e *Engine) Resource(ctx context.Context, account string) (*mailpolicy.Resource, error) {
	var r mailpolicy.Resource
	err := e.DB.QueryRowContext(ctx, `SELECT address,name,kind,location,capacity,booking FROM mailbox_resources WHERE account=$1`, account).
		Scan(&r.Address, &r.Name, &r.Kind, &r.Location, &r.Capacity, &r.Booking)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// Resources lists a domain's resources, or every one for an empty domain.
func (e *Engine) Resources(ctx context.Context, domain string) ([]mailpolicy.Resource, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT address,name,kind,location,capacity,booking FROM mailbox_resources
WHERE $1='' OR split_part(address,'@',2)=$1 ORDER BY name`, strings.ToLower(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.Resource{}
	for rows.Next() {
		var r mailpolicy.Resource
		if err := rows.Scan(&r.Address, &r.Name, &r.Kind, &r.Location, &r.Capacity, &r.Booking); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// bookingEntry is a stored booking and the message holding it.
type bookingEntry struct {
	uid uint32
	obj webmail.Object
}

func (e *Engine) bookings(ctx context.Context, account string) ([]bookingEntry, error) {
	_, messages, err := e.Snapshot(ctx, account, calendarFolder)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]bookingEntry, 0, len(messages))
	for _, m := range messages {
		raw, err := e.Read(ctx, m)
		if err != nil {
			// A booking that can't be read could be a double booking, so
			// this stops rather than carrying on without it.
			return nil, err
		}
		if obj, err := webmail.DecodeBookingObject(raw); err == nil {
			out = append(out, bookingEntry{uid: m.UID, obj: obj})
		}
	}
	return out, nil
}

// lockResource runs fn holding the account's booking lock. The two checks that
// matter, is it free and then book it, must not interleave between replicas.
func (e *Engine) lockResource(ctx context.Context, account string, fn func() error) error {
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7))`, "booking:"+account); err != nil {
		return err
	}
	return fn()
}

func (e *Engine) removeBooking(ctx context.Context, account string, entries []bookingEntry, id string) error {
	var uids []uint32
	for _, b := range entries {
		if b.obj.ID == id {
			uids = append(uids, b.uid)
		}
	}
	if len(uids) == 0 {
		return nil
	}
	if err := e.MutateFlags(ctx, account, calendarFolder, uids, []string{`\Deleted`}, 1); err != nil {
		return err
	}
	_, err := e.Expunge(ctx, account, calendarFolder, uids)
	return err
}

func (e *Engine) publishBookings(ctx context.Context, account Account) error {
	entries, err := e.bookings(ctx, account.ID)
	if err != nil {
		return err
	}
	objs := make([]webmail.Object, len(entries))
	for i, b := range entries {
		objs[i] = b.obj
	}
	from, to, blocks := webmail.BookingBusy(objs, account.Address, time.Now().UTC())
	fb := FreeBusy{From: from, To: to, Busy: []BusyBlock{}}
	for _, b := range blocks {
		fb.Busy = append(fb.Busy, BusyBlock{Start: b.Start, End: b.End})
	}
	return e.PublishFreeBusy(ctx, account, fb)
}

// bookResource handles a delivery to a resource, and reports whether it dealt
// with the message. Anything it doesn't deal with is delivered normally, so
// nothing sent to a room is ever lost.
func (s *Service) bookResource(ctx context.Context, d delivery) (bool, error) {
	resource, err := s.engine.Resource(ctx, d.account.ID)
	if err != nil {
		return false, err
	}
	if resource == nil || resource.Booking != mailpolicy.BookingAuto {
		return false, nil
	}
	method, data := calendarPart(d.raw)
	if method != "REQUEST" && method != "CANCEL" {
		return false, nil
	}
	request, err := webmail.ParseBooking(data)
	if err != nil || request.UID == "" || request.Organizer == "" || request.Occurrence {
		s.log.Info("invitation left for a person", "resource", d.account.Address, "error", err)
		return false, nil
	}
	if !sameDomain(d.account.Address, request.Organizer) || !sameDomain(d.account.Address, d.from) {
		s.log.Info("invitation from outside the domain not booked", "resource", d.account.Address)
		return false, nil
	}
	// The organizer and the envelope sender are only what the message says.
	// Mail from outside claiming this domain is accepted unless DMARC is
	// enforced, so those alone let anyone book a room, or cancel a real
	// booking, in a colleague's name. Act only on what the MTA confirmed.
	if !bookingSenderVerified(d.raw, d.account.Address, request.Organizer) {
		s.log.Info("invitation whose sender wasn't verified left for a person", "resource", d.account.Address)
		return false, nil
	}
	status := ""
	err = s.engine.lockResource(ctx, d.account.ID, func() error {
		entries, err := s.engine.bookings(ctx, d.account.ID)
		if err != nil {
			return err
		}
		objs := make([]webmail.Object, len(entries))
		for i, b := range entries {
			objs[i] = b.obj
		}
		id := webmail.BookingObjectID(request.UID)
		if method == "CANCEL" {
			if webmail.BookingOwnedBy(objs, request.UID, request.Organizer) {
				return s.engine.removeBooking(ctx, d.account.ID, entries, id)
			}
			return nil
		}
		decision, err := webmail.DecideBooking(data, objs)
		if err != nil {
			return err
		}
		switch decision {
		case webmail.BookingStale:
			return nil
		case webmail.BookingDecline:
			status = "DECLINED"
			return nil
		}
		raw, _, err := webmail.BookingObject(data, time.Now())
		if err != nil {
			return err
		}
		if err := s.engine.Create(ctx, d.account.ID, calendarFolder); err != nil && !errors.Is(err, ErrExists) {
			return err
		}
		// The new version goes in before the old one comes out, so a failure
		// between them can't lose a booking someone relies on.
		if _, err := s.engine.Append(ctx, d.account.ID, calendarFolder, raw, nil, time.Now(), ""); err != nil {
			return err
		}
		if err := s.engine.removeBooking(ctx, d.account.ID, entries, id); err != nil {
			return err
		}
		status = "ACCEPTED"
		return nil
	})
	if err != nil {
		return false, err
	}
	if err := s.engine.publishBookings(ctx, d.account); err != nil {
		s.log.Warn("resource free/busy not published", "resource", d.account.Address, "error", err)
	}
	if status != "" {
		s.replyToBooking(ctx, d.account.Address, resource.Name, request.Organizer, data, status)
	}
	return true, nil
}

// replyToBooking sends the answer. The decision stands if this fails: the
// event's guest list simply keeps showing the room as not having replied.
func (s *Service) replyToBooking(ctx context.Context, address, name, organizer string, data []byte, status string) {
	if s.cfg.Sieve.SubmitAddr == "" {
		s.log.Warn("resource can't answer without sieve.submit_addr", "resource", address)
		return
	}
	raw, err := webmail.BookingReply(address, name, data, status, time.Now())
	if err == nil {
		err = s.submit(ctx, address, []string{organizer}, raw)
	}
	if err != nil {
		s.log.Warn("resource answer not sent", "resource", address, "error", err)
	}
}

// bookingSenderVerified reports whether the MTA confirmed that organizer
// sent raw: a signed-in user sending as exactly that address, or mail that
// passed DMARC for the resource's own domain. DMARC vouches for the domain
// only, so it covers a colleague's mail from elsewhere, not who in the domain
// sent it.
func bookingSenderVerified(raw []byte, resource, organizer string) bool {
	switch kind, value := mailpolicy.SenderVerified(raw); kind {
	case "auth":
		return strings.EqualFold(value, organizer)
	case "dmarc":
		return sameDomain(resource, "x@"+value) && sameDomain(resource, organizer)
	}
	return false
}

func sameDomain(a, b string) bool {
	return a != "" && strings.EqualFold(a[strings.LastIndexByte(a, '@')+1:], b[strings.LastIndexByte(b, '@')+1:]) && strings.Contains(b, "@")
}
