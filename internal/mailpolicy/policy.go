// Package mailpolicy describes what a mailbox account may do: its class of
// service and the per-account overrides on top of it.
//
// A class of service is a named set of settings (quota, size and sending
// limits, which protocols may be used, which features are on). Every domain
// can name a class its accounts use by default, and an account can name its
// own class and override single settings. An account's effective policy is
// worked out field by field, most specific first:
//
//	account override > account's class > domain's class > "default" class > built-in default
//
// The mailbox service stores the classes and assignments and answers for
// them (internal/mailbox/policy.go); the MTA, the provisioning CLI and the
// dashboard use the types and the client in this package. Keeping the types
// here, with no other dependencies, lets all of them agree on one wire
// format.
package mailpolicy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultClass is the class every account falls back to. It always exists
// and can't be deleted, so "no class set" has one meaning everywhere.
const DefaultClass = "default"

// Protocol names, as used in Settings and Effective.Allows.
const (
	IMAP       = "imap"
	POP3       = "pop3"
	Webmail    = "webmail"
	DAV        = "dav" // CalDAV and CardDAV
	Submission = "submission"
)

// FiltersOffMessage is the ManageSieve refusal for an account whose class
// turns filters off. The webmail recognises it to explain the empty filters
// page, so both sides use this one string.
const FiltersOffMessage = "Filters are turned off for this account"

// Protocols lists every protocol a policy can allow or refuse.
// ManageSieve isn't among them: it only serves the webmail's filter editor,
// so the Filters feature decides it.
var Protocols = []string{IMAP, POP3, Webmail, DAV, Submission}

// Settings is one layer of policy: a class of service, or an account's own
// overrides. A nil field is unset and falls through to the next layer. For
// the limits, 0 means unlimited, which is different from unset.
type Settings struct {
	QuotaBytes           *int64 `json:"quota_bytes,omitempty"`
	MaxMessageBytes      *int64 `json:"max_message_bytes,omitempty"`
	MaxAttachmentBytes   *int64 `json:"max_attachment_bytes,omitempty"`
	MessagesPerHour      *int   `json:"messages_per_hour,omitempty"`
	RecipientsPerMessage *int   `json:"recipients_per_message,omitempty"`
	RecipientsPerDay     *int   `json:"recipients_per_day,omitempty"`
	// MaxForwardAddresses bounds how many addresses an account's mail may
	// be forwarded to (the directory's elemtaForwardTo).
	MaxForwardAddresses *int `json:"max_forward_addresses,omitempty"`
	// MaxSenderRules bounds a user's allowed and blocked senders together.
	MaxSenderRules *int `json:"max_sender_rules,omitempty"`

	// Protocols maps a protocol name to whether it is allowed. A missing
	// entry is unset.
	Protocols map[string]bool `json:"protocols,omitempty"`

	// ExternalForwarding lets filters redirect mail outside the server.
	ExternalForwarding *bool `json:"external_forwarding,omitempty"`
	// AddressBook offers the user the organisation's address book (the
	// accounts and lists of their domain) when they write. Off unless a
	// class turns it on.
	AddressBook *bool `json:"address_book,omitempty"`
	// Filters lets the user keep Sieve filters, vacation replies included.
	Filters *bool `json:"filters,omitempty"`
	// RequireAppPasswords makes mail apps sign in with app passwords, as if
	// every account in the class had chosen it themselves.
	RequireAppPasswords *bool `json:"require_app_passwords,omitempty"`
	// RequireTwoFactor makes webmail users set up two-step verification
	// before they can use the webmail.
	RequireTwoFactor *bool `json:"require_two_factor,omitempty"`

	// Retention, in days; 0 keeps mail forever. TrashDays, JunkDays and SentDays
	// count from when a message reached that folder; RetentionDays deletes
	// mail in every mail folder by the message's own date.
	TrashDays *int `json:"trash_days,omitempty"`
	JunkDays  *int `json:"junk_days,omitempty"`
	// QuarantineDays empties the Quarantine folder. Unlike the others it has
	// a default: nobody chose to keep this mail, and most of it is spam.
	QuarantineDays *int `json:"quarantine_days,omitempty"`
	SentDays       *int `json:"sent_days,omitempty"`
	RetentionDays  *int `json:"retention_days,omitempty"`
	// LegalHold keeps everything: mail the user deletes is held out of
	// sight, retention skips the account, and it can't be purged.
	LegalHold *bool `json:"legal_hold,omitempty"`
}

// Effective is a fully worked-out policy. Source names the layer each
// setting came from ("account", "class <name>", "domain class <name>",
// "default class", "built-in"), for administrators asking "why".
type Effective struct {
	Address              string            `json:"address"`
	Class                string            `json:"class"`
	QuotaBytes           int64             `json:"quota_bytes"`
	MaxMessageBytes      int64             `json:"max_message_bytes"`
	MaxAttachmentBytes   int64             `json:"max_attachment_bytes"`
	MessagesPerHour      int               `json:"messages_per_hour"`
	RecipientsPerMessage int               `json:"recipients_per_message"`
	RecipientsPerDay     int               `json:"recipients_per_day"`
	MaxForwardAddresses  int               `json:"max_forward_addresses"`
	MaxSenderRules       int               `json:"max_sender_rules"`
	AddressBook          bool              `json:"address_book"`
	Protocols            map[string]bool   `json:"protocols"`
	ExternalForwarding   bool              `json:"external_forwarding"`
	Filters              bool              `json:"filters"`
	RequireAppPasswords  bool              `json:"require_app_passwords"`
	RequireTwoFactor     bool              `json:"require_two_factor"`
	TrashDays            int               `json:"trash_days"`
	JunkDays             int               `json:"junk_days"`
	QuarantineDays       int               `json:"quarantine_days"`
	SentDays             int               `json:"sent_days"`
	RetentionDays        int               `json:"retention_days"`
	LegalHold            bool              `json:"legal_hold"`
	Source               map[string]string `json:"source,omitempty"`
}

// Allows reports whether the policy lets the account use a protocol.
func (e Effective) Allows(protocol string) bool {
	allowed, ok := e.Protocols[protocol]
	return !ok || allowed
}

// Layer is one named level of the resolution order.
type Layer struct {
	Name     string
	Settings Settings
}

// Forwarding limits. Accounts may forward to DefaultMaxForwardAddresses
// addresses unless a class says otherwise; a class can allow up to
// MaxForwardAddressesLimit, which 0 (unlimited) also means, so one entry
// can't fan mail out without bound.
const (
	DefaultMaxForwardAddresses = 3
	MaxForwardAddressesLimit   = 50
)

// Allowed and blocked senders, together: DefaultMaxSenderRules unless a
// class says otherwise, at most MaxSenderRulesLimit, which 0 also means.
const (
	DefaultMaxSenderRules = 100
	MaxSenderRulesLimit   = 5000
)

// SenderRuleLimit is how many allowed and blocked senders the account may
// keep.
func (e Effective) SenderRuleLimit() int {
	if e.MaxSenderRules <= 0 || e.MaxSenderRules > MaxSenderRulesLimit {
		return MaxSenderRulesLimit
	}
	return e.MaxSenderRules
}

// ForwardLimit is how many forwarding addresses the account may have.
func (e Effective) ForwardLimit() int {
	if e.MaxForwardAddresses <= 0 || e.MaxForwardAddresses > MaxForwardAddressesLimit {
		return MaxForwardAddressesLimit
	}
	return e.MaxForwardAddresses
}

// Builtin is what applies when no layer sets a value: everything allowed,
// nothing limited but forwarding, the user's own choices respected.
// DefaultQuarantineDays is how long held mail stays.
const DefaultQuarantineDays = 30

func Builtin() Effective {
	e := Effective{Protocols: map[string]bool{}, QuarantineDays: DefaultQuarantineDays, ExternalForwarding: true, Filters: true, MaxForwardAddresses: DefaultMaxForwardAddresses, MaxSenderRules: DefaultMaxSenderRules, Source: map[string]string{}}
	for _, p := range Protocols {
		e.Protocols[p] = true
	}
	return e
}

// Resolve layers settings over the built-in defaults, least specific first:
// pass the default class, then the domain's class, then the account's class,
// then the account's overrides. Later layers win field by field.
func Resolve(address, class string, layers ...Layer) Effective {
	e := Builtin()
	e.Address, e.Class = address, class
	set := func(field, source string) { e.Source[field] = source }
	for _, l := range layers {
		s := l.Settings
		if s.QuotaBytes != nil {
			e.QuotaBytes = *s.QuotaBytes
			set("quota_bytes", l.Name)
		}
		if s.MaxMessageBytes != nil {
			e.MaxMessageBytes = *s.MaxMessageBytes
			set("max_message_bytes", l.Name)
		}
		if s.MaxAttachmentBytes != nil {
			e.MaxAttachmentBytes = *s.MaxAttachmentBytes
			set("max_attachment_bytes", l.Name)
		}
		if s.MessagesPerHour != nil {
			e.MessagesPerHour = *s.MessagesPerHour
			set("messages_per_hour", l.Name)
		}
		if s.RecipientsPerMessage != nil {
			e.RecipientsPerMessage = *s.RecipientsPerMessage
			set("recipients_per_message", l.Name)
		}
		if s.RecipientsPerDay != nil {
			e.RecipientsPerDay = *s.RecipientsPerDay
			set("recipients_per_day", l.Name)
		}
		if s.MaxForwardAddresses != nil {
			e.MaxForwardAddresses = *s.MaxForwardAddresses
			set("max_forward_addresses", l.Name)
		}
		if s.MaxSenderRules != nil {
			e.MaxSenderRules = *s.MaxSenderRules
			set("max_sender_rules", l.Name)
		}
		if s.AddressBook != nil {
			e.AddressBook = *s.AddressBook
			set("address_book", l.Name)
		}
		for p, allowed := range s.Protocols {
			e.Protocols[p] = allowed
			set("protocols."+p, l.Name)
		}
		if s.ExternalForwarding != nil {
			e.ExternalForwarding = *s.ExternalForwarding
			set("external_forwarding", l.Name)
		}
		if s.Filters != nil {
			e.Filters = *s.Filters
			set("filters", l.Name)
		}
		if s.RequireAppPasswords != nil {
			e.RequireAppPasswords = *s.RequireAppPasswords
			set("require_app_passwords", l.Name)
		}
		if s.RequireTwoFactor != nil {
			e.RequireTwoFactor = *s.RequireTwoFactor
			set("require_two_factor", l.Name)
		}
		if s.TrashDays != nil {
			e.TrashDays = *s.TrashDays
			set("trash_days", l.Name)
		}
		if s.JunkDays != nil {
			e.JunkDays = *s.JunkDays
			set("junk_days", l.Name)
		}
		if s.QuarantineDays != nil {
			e.QuarantineDays = *s.QuarantineDays
			set("quarantine_days", l.Name)
		}
		if s.SentDays != nil {
			e.SentDays = *s.SentDays
			set("sent_days", l.Name)
		}
		if s.RetentionDays != nil {
			e.RetentionDays = *s.RetentionDays
			set("retention_days", l.Name)
		}
		if s.LegalHold != nil {
			e.LegalHold = *s.LegalHold
			set("legal_hold", l.Name)
		}
	}
	return e
}

var classPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ErrInvalid is wrapped by every validation failure.
var ErrInvalid = errors.New("invalid policy")

// ValidClass checks a class name: lower-case letters, digits, '-' and '_',
// up to 63 characters, so it is safe in URLs, logs and CLI arguments.
func ValidClass(name string) error {
	if !classPattern.MatchString(name) {
		return fmt.Errorf("%w: class names use a-z, 0-9, '-' and '_', up to 63 characters", ErrInvalid)
	}
	return nil
}

// maxBytes bounds size settings at 1 PiB, the same ceiling as quotas, so a
// typo can't wrap a counter.
const maxBytes = int64(1) << 50

// Validate checks that every set value is in range and every protocol name
// is known.
func (s Settings) Validate() error {
	for name, v := range map[string]*int64{"quota_bytes": s.QuotaBytes, "max_message_bytes": s.MaxMessageBytes, "max_attachment_bytes": s.MaxAttachmentBytes} {
		if v != nil && (*v < 0 || *v > maxBytes) {
			return fmt.Errorf("%w: %s must be 0 (unlimited) up to 1 PiB", ErrInvalid, name)
		}
	}
	for name, v := range map[string]*int{"messages_per_hour": s.MessagesPerHour, "recipients_per_message": s.RecipientsPerMessage, "recipients_per_day": s.RecipientsPerDay} {
		if v != nil && (*v < 0 || *v > 10_000_000) {
			return fmt.Errorf("%w: %s must be 0 (unlimited) up to 10000000", ErrInvalid, name)
		}
	}
	if v := s.MaxForwardAddresses; v != nil && (*v < 0 || *v > MaxForwardAddressesLimit) {
		return fmt.Errorf("%w: max_forward_addresses must be 0 (up to %d) to %d", ErrInvalid, MaxForwardAddressesLimit, MaxForwardAddressesLimit)
	}
	if v := s.MaxSenderRules; v != nil && (*v < 0 || *v > MaxSenderRulesLimit) {
		return fmt.Errorf("%w: max_sender_rules must be 0 (up to %d) to %d", ErrInvalid, MaxSenderRulesLimit, MaxSenderRulesLimit)
	}
	for name, v := range map[string]*int{"trash_days": s.TrashDays, "junk_days": s.JunkDays, "quarantine_days": s.QuarantineDays, "sent_days": s.SentDays, "retention_days": s.RetentionDays} {
		if v != nil && (*v < 0 || *v > 36500) {
			return fmt.Errorf("%w: %s must be 0 (keep forever) up to 36500", ErrInvalid, name)
		}
	}
	for p := range s.Protocols {
		if !knownProtocol(p) {
			return fmt.Errorf("%w: unknown protocol %q (known: %s)", ErrInvalid, p, strings.Join(Protocols, ", "))
		}
	}
	return nil
}

func knownProtocol(p string) bool {
	for _, k := range Protocols {
		if k == p {
			return true
		}
	}
	return false
}

// Class is a named class of service.
type Class struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Settings    Settings `json:"settings"`
	// Accounts and Domains count the assignments, so an administrator can
	// see what a change will touch. Filled in by the mailbox service.
	Accounts int `json:"accounts"`
	Domains  int `json:"domains"`
}

// AccountPolicy is what is stored for one account: its class, if it has
// one of its own, and its overrides.
type AccountPolicy struct {
	Address  string   `json:"address"`
	Class    string   `json:"class,omitempty"`
	Settings Settings `json:"settings"`
}

// DomainPolicy names the class a domain's accounts use by default.
type DomainPolicy struct {
	Domain string `json:"domain"`
	Class  string `json:"class,omitempty"`
}

// Addressing (internal/mailbox/addressing.go): what an address that isn't a
// directory account delivers to.

// DomainRoute is a domain's addressing: an alias of another local domain
// (every address there delivers as the same name at the target), and a
// catch-all address for names nothing else claims.
type DomainRoute struct {
	Domain   string `json:"domain"`
	AliasOf  string `json:"alias_of,omitempty"`
	CatchAll string `json:"catch_all,omitempty"`
}

// A domain's status: what happens to everyone in it (internal/mailbox/domain_status.go).
const (
	DomainActive    = "active"
	DomainSuspended = "suspended" // receives mail; nobody may sign in
	DomainDisabled  = "disabled"  // no sign-in, and its mail is refused
)

// DomainStatus is a domain's status.
type DomainStatus struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
}

// Who may post to a distribution list, by envelope sender.
const (
	PostAnyone  = "anyone"
	PostMembers = "members"
	PostDomain  = "domain" // senders in the list's own domain
	PostOwner   = "owner"
)

// PostingPolicies lists the valid posting values.
var PostingPolicies = []string{PostAnyone, PostMembers, PostDomain, PostOwner}

// List is a distribution list: mail to its address goes to every member,
// local or external. Owner receives bounces; with no owner, list mail is
// sent with a null sender and bounces are dropped.
type List struct {
	Address     string   `json:"address"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Owner       string   `json:"owner,omitempty"`
	Posting     string   `json:"posting"`
	Members     []string `json:"members"`
	// MemberCount is filled in listings, which leave Members out.
	MemberCount int `json:"member_count"`
}

// AddressInfo says what, if anything, owns an address.
type AddressInfo struct {
	Address string `json:"address"`
	// Kind is "account", "alias", "list" or "" when the address is free.
	Kind string `json:"kind"`
	// Account is the primary address for an account or alias.
	Account string `json:"account,omitempty"`
}
