package mailbox

// Calendar invitations arriving by mail. A delegate answers for someone whose
// inbox they can't read, so invitations are copied to them at delivery. The
// copy is the same message, untouched, and it goes straight into their INBOX
// without running their filters: it isn't mail to them, and it mustn't be
// forwarded or auto-replied to.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-message"
)

// maxCalendarPart bounds what's read of a calendar part. Invitations are small,
// and this runs at delivery on messages from anyone.
const maxCalendarPart = 1 << 20

var errCalendarPartFound = errors.New("calendar part found")

// calendarPart returns the first text/calendar part of a message, and its iTIP
// method from the part's Content-Type or failing that its own METHOD line.
func calendarPart(raw []byte) (string, []byte) {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return "", nil
	}
	var method string
	var data []byte
	err = entity.Walk(func(_ []int, part *message.Entity, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		kind, params, err := part.Header.ContentType()
		if err != nil || kind != "text/calendar" {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(part.Body, maxCalendarPart))
		if err != nil {
			return err
		}
		method, data = strings.ToUpper(params["method"]), body
		return errCalendarPartFound
	})
	if !errors.Is(err, errCalendarPartFound) {
		return "", nil
	}
	if method == "" {
		method = calendarMethodLine(data)
	}
	return method, data
}

// calendarMethodLine reads METHOD from the calendar text.
func calendarMethodLine(data []byte) string {
	for line := range strings.Lines(string(data)) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(name, "METHOD") {
			return strings.ToUpper(value)
		}
		if strings.EqualFold(name, "BEGIN") && strings.EqualFold(value, "VEVENT") {
			break
		}
	}
	return ""
}

// copyInvitationToDelegates never fails a delivery: the owner still gets their
// invitation if a delegate's mailbox is full.
func (s *Service) copyInvitationToDelegates(ctx context.Context, d delivery) {
	delegates, err := s.engine.calendarDelegates(ctx, d.account.ID)
	if err != nil {
		s.log.Warn("calendar delegates unavailable", "account", d.account.ID, "error", err)
		return
	}
	if len(delegates) == 0 {
		return
	}
	switch method, _ := calendarPart(d.raw); method {
	case "REQUEST", "CANCEL":
	default:
		return
	}
	for _, id := range delegates {
		token := storeToken(d.token, "delegate:"+d.account.ID)
		if _, err := s.engine.Append(ctx, id, "INBOX", d.raw, nil, time.Now(), token); err != nil {
			s.log.Warn("invitation not copied to delegate", "account", d.account.ID, "delegate", id, "error", err)
		}
	}
}
