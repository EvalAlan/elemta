package mailbox

// Which mailbox, or which list, an arriving address means, and delivering
// to a distribution list.
//
// A recipient resolves in this order: a directory account or one of its
// aliases; a distribution list; the same name at the domain this one is an
// alias of (and that domain's lists); and last the domain's catch-all.
// The MTA asks the mailbox about every local recipient at RCPT (its
// recipient check is an LMTP RCPT here), so every rule here also decides
// what the MTA accepts.
//
// A list delivers to its local members directly, each through their own
// filters, limits and quota, and sends one copy on to its external members
// through SMTP submission, as filter redirects do, so it is signed and
// queued like any other mail. That copy's envelope sender is the list's
// owner, so bounces go to the person who can fix the member list, not to
// whoever posted.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-smtp"
)

// listHeader marks a message a list has sent on. A list that sees its own
// mark again stops, so two lists that include each other (directly or
// through outside forwarding) can't loop.
const listHeader = "X-Elemta-List"

// maxListDepth bounds nested lists.
const maxListDepth = 5

// recipient is what an address resolved to: an account, or a list.
type recipient struct {
	account Account
	list    string // the list's address, when this is a list
}

// resolveRecipient finds the account or list an address delivers to.
// ErrCredentials means nothing claims it.
func (s *Service) resolveRecipient(ctx context.Context, address string) (recipient, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	r, ok, err := s.resolvePlus(ctx, address)
	if ok || err != nil {
		return r, err
	}
	// A disabled account still owns its address (and its tagged ones): its
	// mail is refused, not handed to a catch-all.
	for _, a := range []string{address, withoutTag(address)} {
		if exists, err := s.auth.Exists(ctx, a); err != nil || exists {
			if err != nil {
				return recipient{}, err
			}
			return recipient{}, ErrCredentials
		}
	}
	local, domain, found := strings.Cut(address, "@")
	if !found {
		return recipient{}, ErrCredentials
	}
	route, err := s.route(ctx, domain)
	if err != nil {
		return recipient{}, err
	}
	if route.AliasOf != "" {
		if r, ok, err := s.resolvePlus(ctx, local+"@"+route.AliasOf); ok || err != nil {
			return r, err
		}
		// The target domain's catch-all applies to its aliases too.
		if route, err = s.route(ctx, route.AliasOf); err != nil {
			return recipient{}, err
		}
	}
	if route.CatchAll != "" {
		if r, ok, err := s.resolveDirect(ctx, route.CatchAll); ok || err != nil {
			return r, err
		}
		s.log.Warn("catch-all address doesn't exist", "domain", route.Domain, "catch_all", route.CatchAll)
	}
	return recipient{}, ErrCredentials
}

// Plus addressing: name+anything@domain is delivered as name@domain, so
// people can give each sign-up its own address and file or filter by it
// (Sieve's subaddress extension sees the tag; the delivery keeps the
// address it was sent to). An address that really exists with a + in it
// is found first, and the tagged form of a list reaches the list.
const tagSeparator = "+"

// withoutTag returns the address without its +tag, or itself.
func withoutTag(address string) string {
	local, domain, ok := strings.Cut(address, "@")
	if !ok {
		return address
	}
	if base, _, tagged := strings.Cut(local, tagSeparator); tagged && base != "" {
		return base + "@" + domain
	}
	return address
}

// resolvePlus is resolveDirect, then the same without the tag.
func (s *Service) resolvePlus(ctx context.Context, address string) (recipient, bool, error) {
	r, ok, err := s.resolveDirect(ctx, address)
	if ok || err != nil {
		return r, ok, err
	}
	if base := withoutTag(address); base != address {
		return s.resolveDirect(ctx, base)
	}
	return recipient{}, false, nil
}

// resolveDirect looks an address up as an account, alias or list, without
// domain routing.
func (s *Service) resolveDirect(ctx context.Context, address string) (recipient, bool, error) {
	a, err := s.auth.Resolve(ctx, address)
	if err == nil {
		return recipient{account: a}, true, nil
	}
	if !errors.Is(err, ErrCredentials) {
		return recipient{}, false, err
	}
	if l, err := s.directoryList(ctx, address); err != nil || l != nil {
		if err != nil {
			return recipient{}, false, err
		}
		return recipient{list: l.Address}, true, nil
	}
	isList, err := s.engine.isList(ctx, address)
	if err != nil || !isList {
		return recipient{}, false, err
	}
	return recipient{list: address}, true, nil
}

// mayPost applies a list's posting policy to an envelope sender. A null
// sender (a bounce or an automatic reply) may post only to an open list.
func mayPost(l mailpolicy.List, from string) bool {
	from = strings.ToLower(strings.Trim(strings.TrimSpace(from), "<>"))
	if l.Posting == mailpolicy.PostAnyone || l.Posting == "" {
		return true
	}
	if from == "" {
		return false
	}
	if l.Owner != "" && from == l.Owner {
		return true
	}
	switch l.Posting {
	case mailpolicy.PostMembers:
		for _, m := range l.Members {
			if m == from {
				return true
			}
		}
	case mailpolicy.PostDomain:
		return domainOf(from) == domainOf(l.Address)
	}
	return false
}

// listTarget is one address a list expands to.
type listTarget struct {
	address string
	account *Account // nil for an external member
}

// expandList works out who a list reaches, through nested lists, each
// address once. Members that are this server's accounts are delivered
// locally; anything the directory and the lists don't know is external.
func (s *Service) expandList(ctx context.Context, l mailpolicy.List) ([]listTarget, error) {
	seen := map[string]bool{l.Address: true}
	var out []listTarget
	var walk func(members []string, depth int) error
	walk = func(members []string, depth int) error {
		for _, m := range members {
			if seen[m] {
				continue
			}
			seen[m] = true
			r, err := s.resolveRecipient(ctx, m)
			switch {
			case errors.Is(err, ErrCredentials):
				// Not ours. A member in one of our own domains that
				// doesn't exist is still sent on, and the MTA bounces it
				// to the owner, who can then fix the list.
				out = append(out, listTarget{address: m})
			case err != nil:
				return err
			case r.list != "":
				if depth >= maxListDepth {
					s.log.Warn("nested lists too deep; skipping", "list", l.Address, "member", m)
					continue
				}
				nested, err := s.list(ctx, r.list)
				if err != nil {
					return err
				}
				if err := walk(nested.Members, depth+1); err != nil {
					return err
				}
			default:
				a := r.account
				if seen[a.Address] && a.Address != m {
					continue // an alias of a member already reached
				}
				seen[a.Address] = true
				out = append(out, listTarget{address: m, account: &a})
			}
		}
		return nil
	}
	return out, walk(l.Members, 1)
}

// deliverList delivers a message to a list's members. A permanent refusal
// (the sender may not post) is returned as an SMTP error for the list's
// recipient; a temporary failure makes the MTA retry, and the retry skips
// members already delivered (their delivery tokens) and an external copy
// already sent (the list's sent record).
func (s *Service) deliverList(ctx context.Context, address, from string, raw []byte, token string) error {
	l, err := s.list(ctx, address)
	if err != nil {
		return err
	}
	if !mayPost(l, from) {
		s.log.Info("list post refused", "list", l.Address, "posting", l.Posting)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "You aren't allowed to post to this list"}
	}
	marker := []byte(strings.ToLower(listHeader + ": " + l.Address))
	if bytes.Contains(bytes.ToLower(headerBlock(raw)), marker) {
		s.log.Info("list loop stopped", "list", l.Address)
		return nil
	}
	targets, err := s.expandList(ctx, l)
	if err != nil {
		return err
	}
	msg := listMessage(l, raw)
	var external []string
	for _, t := range targets {
		if t.account == nil {
			external = append(external, t.address)
			continue
		}
		if err := s.deliverListMember(ctx, l, *t.account, t.address, from, msg, token); err != nil {
			return err
		}
	}
	if len(external) == 0 {
		return nil
	}
	if s.cfg.Sieve.SubmitAddr == "" {
		s.log.Warn("list has external members but sieve.submit_addr isn't set; not sent", "list", l.Address)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "List delivery temporarily unavailable"}
	}
	key := "list-v1:" + sum(token+"\x00"+checksumOf(raw))
	if sent, err := s.engine.listSent(ctx, l.Address, key); err != nil || sent {
		return err
	}
	if err := s.submit(ctx, l.Owner, external, msg); err != nil {
		s.log.Warn("list external delivery failed; will retry", "list", l.Address, "error", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "List delivery temporarily unavailable"}
	}
	_, err = s.engine.claimListSent(ctx, l.Address, key, 7*24*time.Hour)
	return err
}

// deliverListMember delivers to one local member. Trouble that belongs to
// that member (their quota, their size limit, their own filter refusing it)
// is logged and skipped: one full mailbox mustn't bounce the message for
// the whole list. Only a temporary failure of the mailbox service itself is
// returned, so the delivery is retried.
func (s *Service) deliverListMember(ctx context.Context, l mailpolicy.List, a Account, rcpt, from string, msg []byte, token string) error {
	if err := s.applyPolicy(ctx, &a); err != nil {
		return err
	}
	if err := s.engine.EnsureAccount(ctx, a); err != nil {
		return err
	}
	largest := int64(-1)
	if refused := sizeRefusal(a.Policy, msg, &largest); refused != nil {
		s.log.Info("list member skipped: over their size limit", "list", l.Address, "account", a.ID)
		return nil
	}
	memberToken := ""
	if token != "" {
		memberToken = sum(token + "\x00list\x00" + l.Address + "\x00" + rcpt)
	}
	err := s.deliver(ctx, delivery{account: a, from: from, rcpt: rcpt, raw: msg, token: memberToken})
	var smtpErr *smtp.SMTPError
	switch {
	case err == nil:
		s.quotaWarning(ctx, a)
		return nil
	case errors.Is(err, ErrQuota), errors.As(err, &smtpErr) && smtpErr.Code >= 500:
		s.log.Info("list member skipped", "list", l.Address, "account", a.ID, "reason", err)
		return nil
	}
	return err
}

// listMessage adds the list's headers: List-Id (RFC 2919), which mail
// programs use to file and filter list mail, and the loop marker.
func listMessage(l mailpolicy.List, raw []byte) []byte {
	local, domain, _ := strings.Cut(l.Address, "@")
	id := "<" + local + "." + domain + ">"
	if l.Name != "" {
		id = oneLine(strings.ReplaceAll(l.Name, "\"", "")) + " " + id
	}
	head := listHeader + ": " + l.Address + "\r\nList-Id: " + id + "\r\n"
	return append([]byte(head), raw...)
}
