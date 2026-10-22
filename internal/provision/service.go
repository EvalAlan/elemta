// Package provision shares mailbox administration between the CLI and dashboard.
package provision

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

var (
	ErrNotFound    = errors.New("mail account not found")
	ErrExists      = errors.New("mail address already exists")
	ErrInvalid     = errors.New("invalid provisioning request")
	ErrUnavailable = errors.New("mail administration is not configured")
)

type Account struct {
	Address    string   `json:"address"`
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	QuotaBytes int64    `json:"quota_bytes"`
	Aliases    []string `json:"aliases"`
	// Forward lists where all of the account's mail goes; with
	// ForwardKeepCopy a copy also stays in the mailbox. SendAs lists the
	// addresses, or @domain, it may send as besides its own. DirectoryClass
	// is a class of service set in the directory itself (read only here;
	// the dashboard assigns classes in the mailbox service).
	Forward         []string `json:"forward"`
	ForwardKeepCopy bool     `json:"forward_keep_copy"`
	SendAs          []string `json:"send_as"`
	DirectoryClass  string   `json:"directory_class,omitempty"`
	// HiddenFromAddressBook keeps the account out of the organisation's
	// address book (role and service accounts).
	HiddenFromAddressBook bool   `json:"hidden_from_address_book"`
	Created               string `json:"created,omitempty"`
	Modified              string `json:"modified,omitempty"`
}
type Create struct {
	Address    string `json:"address"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	QuotaBytes int64  `json:"quota_bytes"`
}
type Patch struct {
	Name       *string `json:"name,omitempty"`
	Status     *string `json:"status,omitempty"`
	QuotaBytes *int64  `json:"quota_bytes,omitempty"`
	// Forward and SendAs replace the whole list; an empty list clears it.
	Forward         *[]string `json:"forward,omitempty"`
	ForwardKeepCopy *bool     `json:"forward_keep_copy,omitempty"`
	SendAs          *[]string `json:"send_as,omitempty"`
	// HiddenFromAddressBook keeps the account out of the address book.
	HiddenFromAddressBook *bool `json:"hidden_from_address_book,omitempty"`
}

// Bounds on the lists an account carries, so one entry can't fan mail out
// or grant itself without bound. The class of service sets the account's
// own forwarding limit (forwardLimit), which can't exceed the first.
const (
	maxForward = mailpolicy.MaxForwardAddressesLimit
	maxSendAs  = 50
)

// SendAsGrant normalises a send-as grant: an address, or @domain for every
// address in a domain.
func SendAsGrant(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if domain, ok := strings.CutPrefix(value, "@"); ok {
		d, err := DomainName(domain)
		if err != nil {
			return "", err
		}
		return "@" + d, nil
	}
	return Address(value)
}

// cleanList normalises a list of addresses (or grants), without duplicates.
func cleanList(raw []string, max int, what string, normal func(string) (string, error)) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range raw {
		if strings.TrimSpace(v) == "" {
			continue
		}
		n, err := normal(v)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > max {
		return nil, fmt.Errorf("%w: at most %d %s", ErrInvalid, max, what)
	}
	return out, nil
}

type Directory interface {
	List(context.Context) ([]Account, error)
	Get(context.Context, string) (Account, error)
	Create(context.Context, Create) (Account, error)
	Update(context.Context, string, Patch) (Account, error)
	Delete(context.Context, string) error
	Alias(context.Context, string, string, bool) (Account, error)
}
type Domain struct {
	Name       string `json:"name"`
	Accounts   int    `json:"accounts"`
	Aliases    int    `json:"aliases"`
	Configured bool   `json:"configured"`
	// AliasOf and CatchAll come from the mailbox service's routes, when
	// its admin API is configured.
	AliasOf  string `json:"alias_of,omitempty"`
	CatchAll string `json:"catch_all,omitempty"`
}
type Domains interface {
	List(context.Context) ([]string, error)
	Set(context.Context, []string) error
}
type Service struct {
	Directory Directory
	Routing   Domains
	// Hooks invalidate webmail sessions and recovery links before disabling or
	// deleting an account, and reset passwords through the shared reset path.
	Revoke            func(context.Context, string) error
	Remove            func(context.Context, string) error
	Reset             func(context.Context, string, string) error
	MinPasswordLength int
	// Mailbox is the mailbox service's admin API: classes of service and
	// purging. Nil when it isn't configured (ELEMTA_MAILBOX_ADMIN_TOKEN).
	Mailbox *mailpolicy.Client
}

var localPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]*$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

func DomainName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("%w: enter a domain name", ErrInvalid)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || !labelPattern.MatchString(label) {
			return "", fmt.Errorf("%w: invalid domain name", ErrInvalid)
		}
	}
	return name, nil
}
func Address(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	parts := strings.Split(value, "@")
	if len(parts) != 2 || len(parts[0]) > 64 || !localPattern.MatchString(parts[0]) || strings.Contains(parts[0], "..") || strings.HasSuffix(parts[0], ".") {
		return "", fmt.Errorf("%w: enter a mailbox address", ErrInvalid)
	}
	domain, err := DomainName(parts[1])
	if err != nil {
		return "", err
	}
	if len(value) > 254 {
		return "", fmt.Errorf("%w: address is too long", ErrInvalid)
	}
	return parts[0] + "@" + domain, nil
}
func ParseQuota(raw string) (int64, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "" || value == "UNLIMITED" {
		return 0, nil
	}
	multiplier := int64(1)
	for _, suffix := range []struct {
		name   string
		factor int64
	}{{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(value, suffix.name) {
			value = strings.TrimSpace(strings.TrimSuffix(value, suffix.name))
			multiplier = suffix.factor
			break
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 || n > (1<<50)/multiplier {
		return 0, fmt.Errorf("%w: quota must be 0 (unlimited) or a size such as 5G, up to 1 PiB", ErrInvalid)
	}
	return n * multiplier, nil
}
func (s *Service) password(value string) error {
	min := s.MinPasswordLength
	if min < 10 {
		min = 10
	}
	if utf8.RuneCountInString(value) < min || len(value) > 256 {
		return fmt.Errorf("%w: password must contain at least %d characters and at most 256 bytes", ErrInvalid, min)
	}
	return nil
}
func validName(name string) bool {
	return strings.TrimSpace(name) != "" && utf8.RuneCountInString(name) <= 120 && strings.IndexFunc(name, unicode.IsControl) < 0
}
func (s *Service) List(ctx context.Context) ([]Account, error) {
	if s == nil || s.Directory == nil {
		return nil, ErrUnavailable
	}
	return s.Directory.List(ctx)
}
func (s *Service) Get(ctx context.Context, raw string) (Account, error) {
	address, err := Address(raw)
	if err != nil {
		return Account{}, err
	}
	return s.Directory.Get(ctx, address)
}
func (s *Service) configured(ctx context.Context, address string) error {
	names, err := s.Routing.List(ctx)
	if err != nil {
		return err
	}
	domain := strings.SplitN(address, "@", 2)[1]
	for _, name := range names {
		if strings.EqualFold(name, domain) {
			return nil
		}
	}
	return fmt.Errorf("%w: configure domain %s first", ErrInvalid, domain)
}
func (s *Service) Create(ctx context.Context, in Create) (Account, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return Account{}, err
	}
	defer unlock()

	address, err := Address(in.Address)
	if err != nil {
		return Account{}, err
	}
	in.Address = address
	in.Name = strings.TrimSpace(in.Name)
	if !validName(in.Name) {
		return Account{}, fmt.Errorf("%w: enter a display name up to 120 characters", ErrInvalid)
	}
	if in.QuotaBytes < 0 || in.QuotaBytes > 1<<50 {
		return Account{}, fmt.Errorf("%w: invalid quota", ErrInvalid)
	}
	if err = s.password(in.Password); err != nil {
		return Account{}, err
	}
	if err = s.configured(ctx, address); err != nil {
		return Account{}, err
	}
	if err = s.notList(ctx, address); err != nil {
		return Account{}, err
	}
	account, err := s.Directory.Create(ctx, in)
	return account, errors.Join(err, s.notify())
}
func (s *Service) Update(ctx context.Context, raw string, p Patch) (Account, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return Account{}, err
	}
	defer unlock()

	address, err := Address(raw)
	if err != nil {
		return Account{}, err
	}
	if p.Name != nil {
		value := strings.TrimSpace(*p.Name)
		p.Name = &value
		if !validName(value) {
			return Account{}, fmt.Errorf("%w: invalid display name", ErrInvalid)
		}
	}
	if p.Status != nil && *p.Status != "active" && *p.Status != "suspended" && *p.Status != "disabled" {
		return Account{}, fmt.Errorf("%w: status must be active, suspended or disabled", ErrInvalid)
	}
	if p.QuotaBytes != nil && (*p.QuotaBytes < 0 || *p.QuotaBytes > 1<<50) {
		return Account{}, fmt.Errorf("%w: invalid quota", ErrInvalid)
	}
	if p.Forward != nil {
		forward, err := cleanList(*p.Forward, maxForward, "forwarding addresses", Address)
		if err != nil {
			return Account{}, err
		}
		if slices.Contains(forward, address) {
			return Account{}, fmt.Errorf("%w: an account can't forward to itself", ErrInvalid)
		}
		if limit, err := s.forwardLimit(ctx, address); err != nil {
			return Account{}, err
		} else if len(forward) > limit {
			return Account{}, fmt.Errorf("%w: this account's class of service allows %d forwarding addresses", ErrInvalid, limit)
		}
		p.Forward = &forward
	}
	if p.SendAs != nil {
		grants, err := cleanList(*p.SendAs, maxSendAs, "send-as addresses", SendAsGrant)
		if err != nil {
			return Account{}, err
		}
		p.SendAs = &grants
	}
	if p.Name == nil && p.Status == nil && p.QuotaBytes == nil && p.Forward == nil && p.ForwardKeepCopy == nil && p.SendAs == nil && p.HiddenFromAddressBook == nil {
		return Account{}, fmt.Errorf("%w: no changes supplied", ErrInvalid)
	}
	// Suspending, like disabling, ends the account's sessions: webmail
	// sign-ins and recovery links stop working at once.
	if p.Status != nil && *p.Status != "active" {
		if _, err = s.Directory.Get(ctx, address); err != nil {
			return Account{}, err
		}
		if s.Revoke == nil {
			return Account{}, ErrUnavailable
		}
		if err = s.Revoke(ctx, address); err != nil {
			return Account{}, err
		}
	}
	account, err := s.Directory.Update(ctx, address, p)
	if p.Status != nil && *p.Status != "active" {
		err = errors.Join(err, s.Revoke(ctx, address))
	}
	return account, errors.Join(err, s.notify())
}
func (s *Service) Delete(ctx context.Context, raw string) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	address, err := Address(raw)
	if err != nil {
		return err
	}
	if _, err = s.Directory.Get(ctx, address); err != nil {
		return err
	}
	revoke := s.Remove
	if revoke == nil {
		revoke = s.Revoke
	}
	if revoke == nil {
		return ErrUnavailable
	}
	if err = revoke(ctx, address); err != nil {
		return err
	}
	err = s.Directory.Delete(ctx, address)
	return errors.Join(err, revoke(ctx, address), s.notify())
}
func (s *Service) Password(ctx context.Context, raw, value string) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	address, err := Address(raw)
	if err != nil {
		return err
	}
	if err = s.password(value); err != nil {
		return err
	}
	if _, err = s.Directory.Get(ctx, address); err != nil {
		return err
	}
	if s.Reset == nil {
		return ErrUnavailable
	}
	return s.Reset(ctx, address, value)
}
func (s *Service) Alias(ctx context.Context, raw, alias string, add bool) (Account, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return Account{}, err
	}
	defer unlock()

	address, err := Address(raw)
	if err != nil {
		return Account{}, err
	}
	alias, err = Address(alias)
	if err != nil {
		return Account{}, err
	}
	if alias == address {
		return Account{}, fmt.Errorf("%w: alias must differ from the primary address", ErrInvalid)
	}
	if add {
		if err = s.configured(ctx, alias); err != nil {
			return Account{}, err
		}
		if err = s.notList(ctx, alias); err != nil {
			return Account{}, err
		}
	}
	account, err := s.Directory.Alias(ctx, address, alias, add)
	return account, errors.Join(err, s.notify())
}
func (s *Service) Domains(ctx context.Context) ([]Domain, error) {
	names, err := s.Routing.List(ctx)
	if err != nil {
		return nil, err
	}
	accounts, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	values := map[string]*Domain{}
	for _, name := range names {
		values[name] = &Domain{Name: name, Configured: true}
	}
	get := func(address string) *Domain {
		name := strings.SplitN(address, "@", 2)
		if len(name) != 2 {
			return nil
		}
		if values[name[1]] == nil {
			values[name[1]] = &Domain{Name: name[1]}
		}
		return values[name[1]]
	}
	for _, account := range accounts {
		if d := get(account.Address); d != nil {
			d.Accounts++
		}
		for _, alias := range account.Aliases {
			if d := get(alias); d != nil {
				d.Aliases++
			}
		}
	}
	if s.Mailbox != nil {
		// Routes are a nicety in this listing; without them it still works.
		if routes, err := s.Mailbox.Routes(ctx); err == nil {
			for _, r := range routes {
				if d := values[r.Domain]; d != nil {
					d.AliasOf, d.CatchAll = r.AliasOf, r.CatchAll
				}
			}
		}
	}
	out := make([]Domain, 0, len(values))
	for _, d := range values {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (s *Service) Domain(ctx context.Context, raw string, add bool) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.setDomain(ctx, raw, add)
}

// setDomain adds or removes a local domain; the caller holds the lock.
func (s *Service) setDomain(ctx context.Context, raw string, add bool) error {
	name, err := DomainName(raw)
	if err != nil {
		return err
	}
	domains, err := s.Domains(ctx)
	if err != nil {
		return err
	}
	names := []string{}
	found := false
	for _, domain := range domains {
		if domain.Name == name {
			found = domain.Configured
			if !add && (domain.Accounts > 0 || domain.Aliases > 0) {
				return fmt.Errorf("%w: remove accounts and aliases in this domain first", ErrInvalid)
			}
		}
		if domain.Configured && domain.Name != name {
			names = append(names, domain.Name)
		}
	}
	if add {
		if found {
			return ErrExists
		}
		names = append(names, name)
	} else {
		if !found {
			return ErrNotFound
		}
		if len(names) == 0 {
			return fmt.Errorf("%w: at least one local domain is required", ErrInvalid)
		}
	}
	sort.Strings(names)
	return s.Routing.Set(ctx, names)
}

func (s *Service) lock(ctx context.Context) (func(), error) {
	if locker, ok := s.Routing.(interface {
		Lock(context.Context) (func(), error)
	}); ok {
		unlock, err := locker.Lock(ctx)
		if err != nil {
			return nil, err
		}
		// Check shared cache invalidation is writable before changing the directory.
		if err = s.notify(); err != nil {
			unlock()
			return nil, err
		}
		return unlock, nil
	}
	return func() {}, nil
}

func (s *Service) notify() error {
	if notifier, ok := s.Routing.(interface{ Notify() error }); ok {
		if err := notifier.Notify(); err != nil {
			return fmt.Errorf("directory may have changed, but SMTP cache invalidation failed: %w", err)
		}
	}
	return nil
}

// MailboxAdmin returns the mailbox admin API, or explains how to set it up.
func (s *Service) MailboxAdmin() (*mailpolicy.Client, error) {
	if s == nil || s.Mailbox == nil {
		return nil, fmt.Errorf("%w: set %s (and %s if the mailbox isn't at [auth] mailbox_security_url) to manage classes of service and purge mailboxes", ErrUnavailable, mailpolicy.TokenEnv, mailpolicy.URLEnv)
	}
	return s.Mailbox, nil
}

// Purge removes all mailbox data for an address whose account has already
// been deleted: messages, folders, filters, security settings and policy.
// It refuses an account the directory still has, so a live mailbox can't be
// emptied by mistake; deleting the account first is the deliberate step.
func (s *Service) Purge(ctx context.Context, raw string) (mailpolicy.PurgeResult, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return mailpolicy.PurgeResult{}, err
	}
	address, err := Address(raw)
	if err != nil {
		return mailpolicy.PurgeResult{}, err
	}
	switch _, err := s.Directory.Get(ctx, address); {
	case err == nil:
		return mailpolicy.PurgeResult{}, fmt.Errorf("%w: %s still exists; delete the account before purging its mailbox", ErrInvalid, address)
	case !errors.Is(err, ErrNotFound):
		return mailpolicy.PurgeResult{}, err
	}
	return mailbox.Purge(ctx, address)
}

// ResetTwoFactor requires a directory account so an old retained mailbox
// cannot be changed through a recycled address.
func (s *Service) ResetTwoFactor(ctx context.Context, raw string) error {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return err
	}
	address, err := Address(raw)
	if err != nil {
		return err
	}
	if _, err := s.Directory.Get(ctx, address); err != nil {
		return err
	}
	return mailbox.ResetTwoFactor(ctx, address)
}

func (s *Service) Shares(ctx context.Context, raw string) ([]mailpolicy.Share, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return nil, err
	}
	address, err := Address(raw)
	if err != nil {
		return nil, err
	}
	return mailbox.Shares(ctx, address)
}

func (s *Service) GrantShare(ctx context.Context, rawMailbox, rawMember string, canSend bool) (mailpolicy.Share, error) {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return mailpolicy.Share{}, err
	}
	address, err := Address(rawMailbox)
	if err != nil {
		return mailpolicy.Share{}, err
	}
	member, err := Address(rawMember)
	if err != nil {
		return mailpolicy.Share{}, err
	}
	return mailbox.GrantShare(ctx, address, member, canSend)
}

func (s *Service) RevokeShare(ctx context.Context, rawMailbox, rawMember string) error {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return err
	}
	address, err := Address(rawMailbox)
	if err != nil {
		return err
	}
	member, err := Address(rawMember)
	if err != nil {
		return err
	}
	return mailbox.RevokeShare(ctx, address, member)
}

// CheckPurgeable reports why an account's mailbox couldn't be purged now,
// before anything is changed: delete-and-purge checks it first, so a held
// account isn't deleted only for the purge to be refused.
func (s *Service) CheckPurgeable(ctx context.Context, raw string) error {
	mailbox, err := s.MailboxAdmin()
	if err != nil {
		return err
	}
	address, err := Address(raw)
	if err != nil {
		return err
	}
	view, err := mailbox.Account(ctx, address)
	if err != nil {
		if errors.Is(err, mailpolicy.ErrNotFound) {
			return nil // nothing kept for it; purging is a no-op
		}
		return err
	}
	if view.Effective.LegalHold {
		return fmt.Errorf("%w: %s is on legal hold; lift the hold (set-policy --legal-hold off) before purging", ErrInvalid, address)
	}
	return nil
}

// forwardLimit is how many forwarding addresses the account's class of
// service allows: asked of the mailbox service, or the default when its
// admin API isn't configured.
func (s *Service) forwardLimit(ctx context.Context, address string) (int, error) {
	if s.Mailbox == nil {
		return mailpolicy.DefaultMaxForwardAddresses, nil
	}
	eff, err := s.Mailbox.Effective(ctx, address)
	if err != nil {
		return 0, fmt.Errorf("checking the forwarding limit: %w", err)
	}
	return eff.ForwardLimit(), nil
}
