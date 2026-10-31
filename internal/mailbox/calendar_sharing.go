package mailbox

// Calendar sharing. An owner grants someone access to their calendar, which
// lives in the hidden Calendar folder of their account (internal/webmail).
//
// The webmail reaches it with the member's own password, as it does a shared
// mailbox, but this login is its own path rather than a variant of that one,
// for two reasons. A calendar grant opens one folder, so nothing that accepts a
// mailbox login may accept this one: login and securityLogin both refuse the
// name, and an IMAP session holding it refuses everything but that folder. And
// it is only taken on the webmail's internal listener, because the webmail is
// what hides private events from someone with view access. On a public listener
// that person could read the raw objects.

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-imap/v2"
)

const (
	// calendarFolder is the folder a calendar grant opens.
	calendarFolder = "Calendar"
	// calendarLoginSuffix ends the login name: member|owner|calendar.
	calendarLoginSuffix = "|calendar"

	CalendarView     = "view"
	CalendarEdit     = "edit"
	CalendarDelegate = "delegate"
)

func validCalendarLevel(level string) bool {
	return level == CalendarView || level == CalendarEdit || level == CalendarDelegate
}

// GrantCalendar shares owner's calendar with member, or changes their level.
func (e *Engine) GrantCalendar(ctx context.Context, owner, member Account, level string) (mailpolicy.CalendarShare, error) {
	if !validCalendarLevel(level) {
		return mailpolicy.CalendarShare{}, errors.Join(mailpolicy.ErrInvalid, errors.New("level must be view, edit or delegate"))
	}
	if owner.ID == "" || member.ID == "" || owner.ID == member.ID {
		return mailpolicy.CalendarShare{}, errors.Join(mailpolicy.ErrInvalid, errors.New("choose someone other than the calendar's owner"))
	}
	ownerDomain := owner.Address[strings.LastIndexByte(owner.Address, '@')+1:]
	memberDomain := member.Address[strings.LastIndexByte(member.Address, '@')+1:]
	if !strings.EqualFold(ownerDomain, memberDomain) {
		return mailpolicy.CalendarShare{}, errors.Join(mailpolicy.ErrInvalid, errors.New("a calendar can only be shared within its domain"))
	}
	if err := e.EnsureAccount(ctx, owner); err != nil {
		return mailpolicy.CalendarShare{}, err
	}
	if err := e.EnsureAccount(ctx, member); err != nil {
		return mailpolicy.CalendarShare{}, err
	}
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_calendar_shares(owner,member,level) VALUES($1,$2,$3)
ON CONFLICT(owner,member) DO UPDATE SET level=EXCLUDED.level`, owner.ID, member.ID, level)
	return mailpolicy.CalendarShare{Owner: owner.Address, OwnerID: owner.ID, Member: member.Address, Level: level}, err
}

func (e *Engine) RevokeCalendar(ctx context.Context, owner, member string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_calendar_shares WHERE owner=$1 AND member=$2`, owner, member)
	return err
}

func (e *Engine) calendarShares(ctx context.Context, where, id string) ([]mailpolicy.CalendarShare, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT o.address, o.id, m.address, s.level FROM mailbox_calendar_shares s
JOIN mailbox_accounts o ON o.id=s.owner JOIN mailbox_accounts m ON m.id=s.member
WHERE s.`+where+`=$1 ORDER BY o.address, m.address`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.CalendarShare{}
	for rows.Next() {
		var c mailpolicy.CalendarShare
		if err := rows.Scan(&c.Owner, &c.OwnerID, &c.Member, &c.Level); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CalendarSharesOwned lists who can see owner's calendar.
func (e *Engine) CalendarSharesOwned(ctx context.Context, owner string) ([]mailpolicy.CalendarShare, error) {
	return e.calendarShares(ctx, "owner", owner)
}

// CalendarSharesFor lists the calendars member can see.
func (e *Engine) CalendarSharesFor(ctx context.Context, member string) ([]mailpolicy.CalendarShare, error) {
	return e.calendarShares(ctx, "member", member)
}

// CalendarLevel returns member's access to owner's calendar, or "" for none.
func (e *Engine) CalendarLevel(ctx context.Context, owner, member string) (string, error) {
	var level string
	err := e.DB.QueryRowContext(ctx, `SELECT level FROM mailbox_calendar_shares WHERE owner=$1 AND member=$2`, owner, member).Scan(&level)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return level, err
}

// calendarLogin signs in member|owner|calendar, returning the owner's account
// and the member's level. Each refusal looks like a wrong password, so this
// can't be used to learn who has shared with whom.
func (s *Service) calendarLogin(ctx context.Context, user, password, client string) (Account, string, error) {
	if strings.HasPrefix(password, adminTokenPrefix) {
		return Account{}, "", ErrCredentials
	}
	actorName, ownerName, ok := strings.Cut(strings.TrimSuffix(user, calendarLoginSuffix), "|")
	actorName, ownerName = strings.ToLower(strings.TrimSpace(actorName)), strings.ToLower(strings.TrimSpace(ownerName))
	if !ok || actorName == "" || ownerName == "" || strings.Contains(ownerName, "|") || !strings.Contains(ownerName, "@") {
		return Account{}, "", ErrCredentials
	}
	actor, err := s.login(ctx, actorName, password, false, "", client)
	if err != nil {
		return Account{}, "", err
	}
	owner, err := s.auth.Resolve(ctx, ownerName)
	if err != nil {
		return Account{}, "", err
	}
	if owner.Suspended || owner.Address != ownerName {
		return Account{}, "", ErrCredentials
	}
	level, err := s.engine.CalendarLevel(ctx, owner.ID, actor.ID)
	if err != nil {
		return Account{}, "", err
	}
	if level == "" {
		s.recordLoginFailure(actor.Address, client)
		return Account{}, "", ErrCredentials
	}
	if err := s.applyPolicy(ctx, &owner); err != nil {
		return Account{}, "", err
	}
	if owner.Policy != nil && !owner.Policy.Allows(mailpolicy.Webmail) {
		return Account{}, "", ErrProtocolDisabled
	}
	if err := s.engine.EnsureAccount(ctx, owner); err != nil {
		return Account{}, "", err
	}
	return owner, level, nil
}

func isCalendarLogin(user string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(user)), calendarLoginSuffix)
}

// calendarDenied is the refusal for anything outside a calendar grant.
var calendarDenied = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm, Text: "A calendar share opens the calendar only"}

// calendarSession reports whether this session holds a calendar grant.
func (s *imapSession) calendarSession() bool { return s.calendarLevel != "" }

// allowFolder refuses a calendar session any folder but the calendar.
func (s *imapSession) allowFolder(name string) error {
	if s.calendarSession() && name != calendarFolder {
		return calendarDenied
	}
	return nil
}

// allowWrite is allowFolder for commands that change the folder.
func (s *imapSession) allowWrite(name string) error {
	if err := s.allowFolder(name); err != nil {
		return err
	}
	if s.calendarLevel == CalendarView {
		return calendarDenied
	}
	return nil
}

// allowNone refuses a command a calendar session never needs.
func (s *imapSession) allowNone() error {
	if s.calendarSession() {
		return calendarDenied
	}
	return nil
}
