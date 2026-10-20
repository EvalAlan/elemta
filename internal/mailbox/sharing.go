package mailbox

import (
	"context"
	"errors"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// Share is one person's access to another mailbox. Addresses are presented
// for administration; Postgres stores immutable account identities.
type Share struct {
	Mailbox string `json:"mailbox"`
	Member  string `json:"member"`
	CanSend bool   `json:"can_send"`
}

func (e *Engine) GrantShare(ctx context.Context, mailbox, member Account, canSend bool) (Share, error) {
	if mailbox.ID == "" || member.ID == "" || mailbox.ID == member.ID {
		return Share{}, errors.Join(mailpolicy.ErrInvalid, errors.New("choose two different active accounts"))
	}
	mailboxDomain := mailbox.Address[strings.LastIndexByte(mailbox.Address, '@')+1:]
	memberDomain := member.Address[strings.LastIndexByte(member.Address, '@')+1:]
	if !strings.EqualFold(mailboxDomain, memberDomain) {
		return Share{}, errors.Join(mailpolicy.ErrInvalid, errors.New("a shared mailbox and its member must be in the same domain"))
	}
	if err := e.EnsureAccount(ctx, mailbox); err != nil {
		return Share{}, err
	}
	if err := e.EnsureAccount(ctx, member); err != nil {
		return Share{}, err
	}
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_shares(mailbox,member,can_send) VALUES($1,$2,$3)
ON CONFLICT(mailbox,member) DO UPDATE SET can_send=EXCLUDED.can_send`, mailbox.ID, member.ID, canSend)
	return Share{Mailbox: mailbox.Address, Member: member.Address, CanSend: canSend}, err
}

func (e *Engine) RevokeShare(ctx context.Context, mailbox, member string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_shares WHERE mailbox=$1 AND member=$2`, mailbox, member)
	return err
}

func (e *Engine) SharesForMailbox(ctx context.Context, mailbox string) ([]Share, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT owner.address, person.address, s.can_send
FROM mailbox_shares s JOIN mailbox_accounts owner ON owner.id=s.mailbox
JOIN mailbox_accounts person ON person.id=s.member WHERE s.mailbox=$1 ORDER BY person.address`, mailbox)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Share{}
	for rows.Next() {
		var share Share
		if err := rows.Scan(&share.Mailbox, &share.Member, &share.CanSend); err != nil {
			return nil, err
		}
		out = append(out, share)
	}
	return out, rows.Err()
}

func (e *Engine) SharesForMember(ctx context.Context, member string) ([]Share, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT owner.address, person.address, s.can_send
FROM mailbox_shares s JOIN mailbox_accounts owner ON owner.id=s.mailbox
JOIN mailbox_accounts person ON person.id=s.member WHERE s.member=$1 ORDER BY owner.address`, member)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Share{}
	for rows.Next() {
		var share Share
		if err := rows.Scan(&share.Mailbox, &share.Member, &share.CanSend); err != nil {
			return nil, err
		}
		out = append(out, share)
	}
	return out, rows.Err()
}

func (e *Engine) HasShare(ctx context.Context, mailbox, member string, sending bool) (bool, error) {
	var allowed bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_shares WHERE mailbox=$1 AND member=$2 AND (NOT $3 OR can_send))`, mailbox, member, sending).Scan(&allowed)
	return allowed, err
}
