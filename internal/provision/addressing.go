package provision

// Distribution lists, domain aliases and catch-alls. They are kept by the
// mailbox service (internal/mailbox/addressing.go), so these go through its
// admin API, with the same checks the directory commands make: the domain
// must be local, and an address belongs to one account, alias or list.
// Every change bumps the provisioning generation, so the MTA forgets the
// recipients it had cached and accepts or refuses the new addresses at once.

import (
	"context"
	"errors"
	"fmt"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// notList refuses an address a distribution list already has, when the
// mailbox admin API is configured to say. Without it the directory's own
// reservation is the only check, as before lists existed.
func (s *Service) notList(ctx context.Context, address string) error {
	if s.Mailbox == nil {
		return nil
	}
	info, err := s.Mailbox.Address(ctx, address)
	if err != nil {
		return err
	}
	if info.Kind == "list" {
		return fmt.Errorf("%w: %s is a distribution list", ErrExists, address)
	}
	return nil
}

// Lists returns every distribution list, without members.
func (s *Service) Lists(ctx context.Context) ([]mailpolicy.List, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return nil, err
	}
	return mailbox.Lists(ctx)
}

// GetList returns one list with its members.
func (s *Service) GetList(ctx context.Context, raw string) (mailpolicy.List, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return mailpolicy.List{}, err
	}
	address, err := Address(raw)
	if err != nil {
		return mailpolicy.List{}, err
	}
	return mailbox.List(ctx, address)
}

// PutList creates a list or replaces its settings and members. Its address
// must be in a local domain and not belong to an account or alias.
func (s *Service) PutList(ctx context.Context, l mailpolicy.List) (mailpolicy.List, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return l, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return l, err
	}
	defer unlock()
	if l.Address, err = Address(l.Address); err != nil {
		return l, err
	}
	if err = s.configured(ctx, l.Address); err != nil {
		return l, err
	}
	if l.Owner != "" {
		if l.Owner, err = Address(l.Owner); err != nil {
			return l, fmt.Errorf("owner: %w", err)
		}
	}
	out, err := mailbox.PutList(ctx, l)
	return out, errors.Join(err, s.notify())
}

// ChangeMembers adds and removes list members.
func (s *Service) ChangeMembers(ctx context.Context, raw string, add, remove []string) (mailpolicy.List, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return mailpolicy.List{}, err
	}
	address, err := Address(raw)
	if err != nil {
		return mailpolicy.List{}, err
	}
	return mailbox.ChangeMembers(ctx, address, add, remove)
}

// DeleteList removes a list.
func (s *Service) DeleteList(ctx context.Context, raw string) error {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return err
	}
	address, err := Address(raw)
	if err != nil {
		return err
	}
	return errors.Join(mailbox.DeleteList(ctx, address), s.notify())
}

// Routes lists domain aliases and catch-alls.
func (s *Service) Routes(ctx context.Context) ([]mailpolicy.DomainRoute, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return nil, err
	}
	return mailbox.Routes(ctx)
}

func (s *Service) route(ctx context.Context, domain string) (mailpolicy.DomainRoute, error) {
	routes, err := s.Mailbox.Routes(ctx)
	if err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	for _, r := range routes {
		if r.Domain == domain {
			return r, nil
		}
	}
	return mailpolicy.DomainRoute{Domain: domain}, nil
}

// DomainAlias makes alias deliver as target (every name at alias goes to
// the same name at target), or removes that. Adding it also makes alias a
// local domain, since the MTA must accept mail for it; removing it takes
// the domain off again. Either needs an SMTP restart, as for any domain.
func (s *Service) DomainAlias(ctx context.Context, rawAlias, rawTarget string, add bool) (mailpolicy.DomainRoute, error) {
	if _, err := s.MailboxAdmin(); err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	defer unlock()
	alias, err := DomainName(rawAlias)
	if err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	route, err := s.route(ctx, alias)
	if err != nil {
		return route, err
	}
	if !add {
		if route.AliasOf == "" {
			return route, fmt.Errorf("%w: %s isn't a domain alias", ErrNotFound, alias)
		}
		route.AliasOf = ""
		if route, err = s.Mailbox.SetRoute(ctx, route); err != nil {
			return route, err
		}
		return route, errors.Join(s.setDomain(ctx, alias, false), s.notify())
	}
	target, err := DomainName(rawTarget)
	if err != nil {
		return route, err
	}
	if err = s.configured(ctx, "postmaster@"+target); err != nil {
		return route, err
	}
	if err = s.configured(ctx, "postmaster@"+alias); err == nil {
		return route, fmt.Errorf("%w: %s is already a local domain; an alias domain must be new", ErrExists, alias)
	}
	route.AliasOf = target
	if route, err = s.Mailbox.SetRoute(ctx, route); err != nil {
		return route, err
	}
	if err = s.setDomain(ctx, alias, true); err != nil {
		// Undo the route, so the two stores agree.
		route.AliasOf = ""
		_, undo := s.Mailbox.SetRoute(ctx, route)
		return route, errors.Join(err, undo)
	}
	return route, s.notify()
}

// CatchAll sends mail for unknown names in a local domain to address, or
// with an empty address stops doing so. The address must exist: a catch-all
// pointing nowhere would accept mail and then bounce it.
func (s *Service) CatchAll(ctx context.Context, rawDomain, rawAddress string) (mailpolicy.DomainRoute, error) {
	if _, err := s.MailboxAdmin(); err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	defer unlock()
	domain, err := DomainName(rawDomain)
	if err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	if err = s.configured(ctx, "postmaster@"+domain); err != nil {
		return mailpolicy.DomainRoute{}, err
	}
	route, err := s.route(ctx, domain)
	if err != nil {
		return route, err
	}
	route.CatchAll = ""
	if rawAddress != "" {
		address, err := Address(rawAddress)
		if err != nil {
			return route, err
		}
		info, err := s.Mailbox.Address(ctx, address)
		if err != nil {
			return route, err
		}
		if info.Kind == "" {
			return route, fmt.Errorf("%w: %s isn't an account, alias or list", ErrNotFound, address)
		}
		route.CatchAll = address
	}
	route, err = s.Mailbox.SetRoute(ctx, route)
	return route, errors.Join(err, s.notify())
}
