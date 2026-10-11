package queue

import (
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// Provider-aware throttling.
//
// The shaper treats every destination domain alike: a 4xx backs that domain
// off for a doubling interval. Large mailbox providers do not fit that model
// in two ways.
//
// First, they are not one domain. Gmail's MX hosts serve gmail.com and every
// Google Workspace domain; Microsoft's serve outlook.com, hotmail.com and every
// Microsoft 365 tenant; Yahoo's serve yahoo.com, aol.com and more. They apply
// their rate and reputation limits per sending IP across all of it. Shaping
// per recipient domain lets a sender open ten connections to gmail.com, ten
// more to each Workspace customer, and so on, while Google sees one IP with
// hundreds of connections. So destinations whose MX belongs to a known
// provider share one shaping state, keyed by the provider, matched by MX host
// rather than by recipient domain.
//
// Second, they say what they mean. Gmail's 421 4.7.28, Yahoo's [TSS04] and
// Microsoft's 4.7.650 / RP-00x are explicit statements that this IP is being
// rate or reputation limited. Treating those like any 4xx (a short backoff,
// then full speed again) re-offends immediately. They get a longer backoff
// and a lasting cut in send rate that decays only while the provider stays
// quiet. Conversely, some 4xx replies are about one mailbox (full, or
// receiving too fast), and backing off a whole provider because one
// recipient's inbox is full slows everyone else's mail for nothing.

// ProviderConfig describes a mailbox provider, or overrides a built-in one by
// name.
type ProviderConfig struct {
	Name string `toml:"name" json:"name"`
	// Disabled turns a built-in profile off; its destinations go back to
	// plain per-domain shaping.
	Disabled bool `toml:"disabled" json:"disabled,omitempty"`
	// MXSuffixes match the provider's MX host names: "google.com" matches
	// aspmx.l.google.com. Required for a custom provider; for a built-in,
	// setting it replaces the built-in list.
	MXSuffixes []string `toml:"mx_suffixes" json:"mx_suffixes,omitempty"`
	// MaxConnections caps concurrent deliveries to the provider per source
	// address. Zero uses max_connections_per_domain.
	MaxConnections int `toml:"max_connections" json:"max_connections,omitempty"`
	// MaxMessagesPerMinute caps the send rate per source address. Zero uses
	// [delivery] max_messages_per_minute_per_domain.
	MaxMessagesPerMinute int `toml:"max_messages_per_minute" json:"max_messages_per_minute,omitempty"`
	// ThrottledMessagesPerMinute is the rate after the provider throttles us,
	// halved for each further throttle while the penalty lasts. Zero uses
	// the built-in value, or DefaultThrottledRate.
	ThrottledMessagesPerMinute int `toml:"throttled_messages_per_minute" json:"throttled_messages_per_minute,omitempty"`
	// ThrottleSignals are substrings of a reply that mean the provider is
	// limiting this sender. Matched case-insensitively. For a built-in,
	// these are added to its own.
	ThrottleSignals []string `toml:"throttle_signals" json:"throttle_signals,omitempty"`
	// RecipientSignals are substrings of a 4xx reply that mean one mailbox
	// is the problem, not the sender. Added to a built-in's own.
	RecipientSignals []string `toml:"recipient_signals" json:"recipient_signals,omitempty"`
	// ThrottleBackoff and ThrottleBackoffMax bound the pause after a
	// throttle signal, in seconds. Zero uses the built-in values.
	ThrottleBackoff    int `toml:"throttle_backoff" json:"throttle_backoff,omitempty"`
	ThrottleBackoffMax int `toml:"throttle_backoff_max" json:"throttle_backoff_max,omitempty"`
}

// provider is a resolved profile.
type provider struct {
	name             string
	mxSuffixes       []string
	limits           Limits
	throttleSignals  []string
	recipientSignals []string
	backoff          time.Duration
	backoffMax       time.Duration
}

// builtinProviders are the profiles that apply unless configured otherwise.
//
// The signals are the providers' own documented reply texts:
//   - Google: 421-4.7.28 "unusual rate of unsolicited mail ... temporarily
//     rate limited", and 450-4.2.1 "receiving mail at a rate that prevents
//     additional messages" for one recipient.
//   - Yahoo (also AOL): 421 4.7.0 [TSS04] / [TSS09] "temporarily deferred due
//     to unexpected volume or user complaints".
//   - Microsoft (Outlook.com and Microsoft 365): 451 4.7.650 "temporarily
//     rate limited due to IP reputation", 421 RP-001/002/003 rate limits, and
//     4.7.500 "server busy, please try again later".
//
// No built-in sets a connection or message rate. None of these providers
// publishes one, and a guessed number slows deployments that are well
// within what the provider accepts; what they do publish is how they say
// "slow down", which is what the profiles act on.
func builtinProviders() []*provider {
	return []*provider{
		{
			name:             "gmail",
			mxSuffixes:       []string{"google.com", "googlemail.com"},
			throttleSignals:  []string{"4.7.28", "unusual rate of unsolicited mail", "temporarily rate limited"},
			recipientSignals: []string{"receiving mail at a rate", "4.2.2"},
			backoff:          10 * time.Minute,
			backoffMax:       2 * time.Hour,
		},
		{
			name:             "yahoo",
			mxSuffixes:       []string{"yahoodns.net"},
			throttleSignals:  []string{"[tss04]", "[tss09]", "temporarily deferred due to unexpected volume", "temporarily deferred due to user complaints"},
			recipientSignals: []string{"4.2.2"},
			backoff:          15 * time.Minute,
			backoffMax:       4 * time.Hour,
		},
		{
			name:             "microsoft",
			mxSuffixes:       []string{"protection.outlook.com"},
			throttleSignals:  []string{"4.7.650", "rp-001", "rp-002", "rp-003", "4.7.500", "rate limited due to ip reputation"},
			recipientSignals: []string{"4.2.2"},
			backoff:          10 * time.Minute,
			backoffMax:       2 * time.Hour,
		},
	}
}

// genericRecipientSignals apply to every destination, profiled or not. 4.2.2
// is RFC 3463's "mailbox full": nothing about it concerns the sender's pace.
var genericRecipientSignals = []string{"4.2.2"}

// ProviderRouter maps destinations to provider profiles.
type ProviderRouter struct {
	providers []*provider

	// byDomain remembers which provider a recipient domain's MX belongs to,
	// so a provider in backoff can be refused before the MX lookup. Bounded;
	// losing an entry only costs that lookup.
	mu       sync.Mutex
	byDomain map[string]*provider
}

const maxProviderMemo = 10000

// NewProviderRouter builds the profiles from the built-ins and overrides.
// enabled false returns nil: every destination is shaped per domain.
func NewProviderRouter(enabled bool, overrides []ProviderConfig) (*ProviderRouter, error) {
	if !enabled {
		return nil, nil
	}
	byName := make(map[string]*provider)
	var order []string
	for _, p := range builtinProviders() {
		byName[p.name] = p
		order = append(order, p.name)
	}
	disabled := make(map[string]bool)
	seen := make(map[string]bool)
	for i, oc := range overrides {
		name := strings.ToLower(strings.TrimSpace(oc.Name))
		if name == "" {
			return nil, fmt.Errorf("provider %d has no name", i+1)
		}
		if seen[name] {
			return nil, fmt.Errorf("provider %q is configured twice", name)
		}
		seen[name] = true
		if oc.Disabled {
			disabled[name] = true
			continue
		}
		p, builtin := byName[name]
		if !builtin {
			if len(oc.MXSuffixes) == 0 {
				return nil, fmt.Errorf("provider %q needs mx_suffixes", name)
			}
			p = &provider{name: name}
			byName[name] = p
			order = append(order, name)
		}
		if len(oc.MXSuffixes) > 0 {
			p.mxSuffixes = nil
			for _, sfx := range oc.MXSuffixes {
				sfx = normalizeHost(sfx)
				if sfx == "" {
					return nil, fmt.Errorf("provider %q has an empty mx_suffixes entry", name)
				}
				p.mxSuffixes = append(p.mxSuffixes, sfx)
			}
		}
		for field, v := range map[string]int{
			"max_connections":               oc.MaxConnections,
			"max_messages_per_minute":       oc.MaxMessagesPerMinute,
			"throttled_messages_per_minute": oc.ThrottledMessagesPerMinute,
			"throttle_backoff":              oc.ThrottleBackoff,
			"throttle_backoff_max":          oc.ThrottleBackoffMax,
		} {
			if v < 0 {
				return nil, fmt.Errorf("provider %q: %s is negative", name, field)
			}
		}
		if oc.MaxConnections > 0 {
			p.limits.MaxConnections = oc.MaxConnections
		}
		if oc.MaxMessagesPerMinute > 0 {
			p.limits.MaxMessagesPerMinute = oc.MaxMessagesPerMinute
		}
		if oc.ThrottledMessagesPerMinute > 0 {
			p.limits.ThrottledMessagesPerMinute = oc.ThrottledMessagesPerMinute
		}
		if oc.ThrottleBackoff > 0 {
			p.backoff = time.Duration(oc.ThrottleBackoff) * time.Second
		}
		if oc.ThrottleBackoffMax > 0 {
			p.backoffMax = time.Duration(oc.ThrottleBackoffMax) * time.Second
		}
		for _, sig := range oc.ThrottleSignals {
			if sig = strings.ToLower(strings.TrimSpace(sig)); sig != "" {
				p.throttleSignals = append(p.throttleSignals, sig)
			}
		}
		for _, sig := range oc.RecipientSignals {
			if sig = strings.ToLower(strings.TrimSpace(sig)); sig != "" {
				p.recipientSignals = append(p.recipientSignals, sig)
			}
		}
	}

	r := &ProviderRouter{byDomain: make(map[string]*provider)}
	owner := make(map[string]string)
	for _, name := range order {
		if disabled[name] {
			continue
		}
		p := byName[name]
		for _, sfx := range p.mxSuffixes {
			if prev, dup := owner[sfx]; dup {
				return nil, fmt.Errorf("mx suffix %q is claimed by both %q and %q", sfx, prev, name)
			}
			owner[sfx] = name
		}
		r.providers = append(r.providers, p)
	}
	for name := range disabled {
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("provider %q is disabled but is not a built-in or configured provider", name)
		}
	}
	return r, nil
}

func normalizeHost(h string) string {
	return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), "."), ".")
}

// matchMX returns the provider whose suffix matches the most preferred MX
// host. Only the first record is used: a domain that lists a provider as a
// backup MX is not that provider's customer for pacing purposes, and the
// primary is where its mail goes.
func (r *ProviderRouter) matchMX(domain string, mx []*net.MX) *provider {
	if r == nil {
		return nil
	}
	var found *provider
	if len(mx) > 0 {
		host := normalizeHost(mx[0].Host)
	search:
		for _, p := range r.providers {
			for _, sfx := range p.mxSuffixes {
				if host == sfx || strings.HasSuffix(host, "."+sfx) {
					found = p
					break search
				}
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if found == nil {
		delete(r.byDomain, domain)
		return nil
	}
	if len(r.byDomain) >= maxProviderMemo {
		// Crude, but bounded: a full table is cleared rather than tracked
		// for recency. The cost of a miss is one cached MX lookup.
		r.byDomain = make(map[string]*provider)
	}
	r.byDomain[domain] = found
	return found
}

// known returns the provider last seen for a domain, if any.
func (r *ProviderRouter) known(domain string) *provider {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byDomain[domain]
}

// providerKeyPrefix marks a shaping key that stands for a provider rather
// than a single recipient domain. A domain cannot contain a colon, so the
// two cannot collide.
const providerKeyPrefix = "provider:"

func providerKey(p *provider) string { return providerKeyPrefix + p.name }

// providerOfKey returns the provider name in a shaping key, or "".
func providerOfKey(domain string) string {
	if name, ok := strings.CutPrefix(domain, providerKeyPrefix); ok {
		return name
	}
	return ""
}

// destinationKey is what a delivery to domain is shaped under: the provider
// when the domain's MX is known to belong to one, otherwise the domain.
func destinationKey(p *provider, domain string) string {
	if p == nil {
		return domain
	}
	return providerKey(p)
}

// deferralKind is what a temporary failure says about the sender.
type deferralKind int

const (
	// deferralGeneric is any other 4xx: back off on the usual schedule.
	deferralGeneric deferralKind = iota
	// deferralThrottle is the provider limiting this sender explicitly.
	deferralThrottle
	// deferralRecipient is about specific mailboxes; do not back off.
	deferralRecipient
)

// classifyDeferral reads a temporary failure. The replies come from the
// recipient outcomes when the session got that far (each recipient's own
// reply), otherwise from the error.
//
// A throttle anywhere wins: one throttled recipient means the provider is
// throttling the sender. Recipient-level needs every deferral to be
// recipient-level; a mix means something else is also wrong.
func classifyDeferral(p *provider, err error, outcomes []RecipientOutcome) deferralKind {
	var replies []string
	for _, o := range outcomes {
		if o.Status == RecipientTemporaryFailure && o.Diagnostic != "" {
			replies = append(replies, strings.ToLower(o.Diagnostic))
		}
	}
	if len(replies) == 0 && err != nil {
		replies = append(replies, strings.ToLower(replyText(err)))
	}
	if len(replies) == 0 {
		return deferralGeneric
	}

	if p != nil {
		for _, reply := range replies {
			if containsAny(reply, p.throttleSignals) {
				return deferralThrottle
			}
		}
	}
	recipientSignals := genericRecipientSignals
	if p != nil {
		recipientSignals = p.recipientSignals
	}
	for _, reply := range replies {
		if !isReplyText(reply) || !containsAny(reply, recipientSignals) {
			return deferralGeneric
		}
	}
	return deferralRecipient
}

// isReplyText reports whether a diagnostic looks like an SMTP reply rather
// than a local error that happens to contain digits (a timeout message
// mentioning a port, say). Recipient-level is only decided on real replies.
func isReplyText(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 3 && (s[0] == '4' || s[0] == '5') && allDigits(s[:3])
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// replyText extracts "code text" from an SMTP error, for classifying the
// error itself when there are no per-recipient outcomes.
func replyText(err error) string {
	var tp *textproto.Error
	if errors.As(err, &tp) {
		return fmt.Sprintf("%d %s", tp.Code, tp.Msg)
	}
	return err.Error()
}
