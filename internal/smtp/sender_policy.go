package smtp

// Class-of-service rules for mail a signed-in user sends (internal/mailpolicy
// explains classes). The mailbox service owns the classes; this side asks it
// for a sender's effective policy through the admin API and enforces what
// only the MTA sees:
//
//   - the submission switch (in AuthenticateFrom, app_passwords.go);
//   - recipients per message, at RCPT;
//   - messages per hour and recipients per day, counted per user;
//   - message and attachment size, once the message has arrived.
//
// The rules follow the user, not the connection: mail sent from the webmail
// (an exempt network for app passwords) counts too, as does mail on port 25
// from a signed-in user. Counting uses fixed windows (the clock hour and the
// UTC day), shared through Valkey when VALKEY_ADDR is set, so every MTA node
// counts against the same total; otherwise each node counts on its own.
//
// If the policy can't be fetched the sender is asked to try again later
// (4xx). Sending without knowing the limits would let an account the
// administrator restricted send freely whenever the mailbox service is
// unreachable.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

type senderPolicies struct {
	client   *mailpolicy.Client
	counters sendCounters
	log      *slog.Logger
	ttl      time.Duration
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]cachedPolicy
}

type cachedPolicy struct {
	eff     mailpolicy.Effective
	expires time.Time
}

// newSenderPolicies is nil (no class-of-service rules on sending) unless the
// admin API is configured: ELEMTA_MAILBOX_ADMIN_TOKEN, with the URL from
// ELEMTA_MAILBOX_ADMIN_URL or [auth] mailbox_security_url.
func newSenderPolicies(config *Config, log *slog.Logger) *senderPolicies {
	base := ""
	if config.Auth != nil {
		base = config.Auth.MailboxSecurityURL
	}
	if v := os.Getenv("ELEMTA_AUTH_MAILBOX_SECURITY_URL"); v != "" {
		base = v
	}
	client, err := mailpolicy.FromEnv(base)
	if err != nil {
		if !errors.Is(err, mailpolicy.ErrUnavailable) {
			log.Warn("class-of-service sending rules disabled", "error", err)
		}
		return nil
	}
	p := &senderPolicies{client: client, log: log, ttl: time.Minute, now: time.Now, cache: map[string]cachedPolicy{}}
	if addr := os.Getenv("VALKEY_ADDR"); addr != "" {
		vc, err := valkeyaddr.NewClient(addr, func(o *valkey.ClientOption) { o.DisableCache = true })
		if err == nil {
			p.counters = &valkeyCounters{client: vc, prefix: "elemta:send:"}
		} else {
			log.Warn("sending limits counted per node: Valkey unavailable", "error", err)
		}
	}
	if p.counters == nil {
		p.counters = newMemoryCounters()
	}
	log.Info("class-of-service sending rules enabled")
	return p
}

// policy returns a user's effective policy, cached for a minute: long enough
// that a busy sender costs one lookup per minute, short enough that a change
// an administrator makes applies almost at once.
func (p *senderPolicies) policy(ctx context.Context, user string) (mailpolicy.Effective, error) {
	user = normalUser(user)
	p.mu.Lock()
	c, ok := p.cache[user]
	p.mu.Unlock()
	if ok && p.now().Before(c.expires) {
		return c.eff, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	eff, err := p.client.Effective(ctx, user)
	if err != nil {
		return eff, err
	}
	p.mu.Lock()
	if len(p.cache) > 10000 {
		p.cache = map[string]cachedPolicy{}
	}
	p.cache[user] = cachedPolicy{eff: eff, expires: p.now().Add(p.ttl)}
	p.mu.Unlock()
	return eff, nil
}

// normalUser is the form a username is cached and counted under, so
// "Dana@Example.com" and "dana@example.com" share one set of limits.
func normalUser(user string) string { return strings.ToLower(strings.TrimSpace(user)) }

func (p *senderPolicies) unavailable(user string, err error) error {
	p.log.Warn("sender's class of service unavailable; deferring", "username", user, "error", err)
	return fmt.Errorf("451 4.7.1 Sending limits can't be checked right now; try again later")
}

// checkMail runs at MAIL FROM: the hourly message count and a declared size.
func (p *senderPolicies) checkMail(ctx context.Context, user string, declaredSize int64) error {
	user = normalUser(user)
	eff, err := p.policy(ctx, user)
	if err != nil {
		return p.unavailable(user, err)
	}
	if eff.MaxMessageBytes > 0 && declaredSize > eff.MaxMessageBytes {
		return fmt.Errorf("552 5.3.4 Message is larger than your account may send (%d bytes maximum)", eff.MaxMessageBytes)
	}
	if eff.MessagesPerHour > 0 {
		sent, err := p.counters.messages(ctx, user, p.now())
		if err != nil {
			return p.unavailable(user, err)
		}
		if sent >= eff.MessagesPerHour {
			p.log.Info("sending limit reached", "username", user, "limit", "messages_per_hour", "value", eff.MessagesPerHour)
			return fmt.Errorf("451 4.7.1 Your account has sent its %d messages for this hour; try again later", eff.MessagesPerHour)
		}
	}
	return nil
}

// checkRcpt runs at RCPT, with the recipients already accepted for this
// message.
func (p *senderPolicies) checkRcpt(ctx context.Context, user string, accepted int) error {
	user = normalUser(user)
	eff, err := p.policy(ctx, user)
	if err != nil {
		return p.unavailable(user, err)
	}
	if eff.RecipientsPerMessage > 0 && accepted >= eff.RecipientsPerMessage {
		return fmt.Errorf("452 4.5.3 Too many recipients: your account may send to %d per message", eff.RecipientsPerMessage)
	}
	if eff.RecipientsPerDay > 0 {
		today, err := p.counters.recipients(ctx, user, p.now())
		if err != nil {
			return p.unavailable(user, err)
		}
		if today+accepted >= eff.RecipientsPerDay {
			p.log.Info("sending limit reached", "username", user, "limit", "recipients_per_day", "value", eff.RecipientsPerDay)
			return fmt.Errorf("452 4.7.1 Your account has reached its %d recipients for today", eff.RecipientsPerDay)
		}
	}
	return nil
}

// checkContent runs once the message has arrived. raw is nil when only the
// size is known; the attachment limit then needs readRaw.
func (p *senderPolicies) checkContent(ctx context.Context, user string, size int64, readRaw func() ([]byte, error)) error {
	eff, err := p.policy(ctx, user)
	if err != nil {
		return p.unavailable(user, err)
	}
	if eff.MaxMessageBytes > 0 && size > eff.MaxMessageBytes {
		return fmt.Errorf("552 5.3.4 Message is larger than your account may send (%d bytes maximum)", eff.MaxMessageBytes)
	}
	if eff.MaxAttachmentBytes > 0 {
		raw, err := readRaw()
		if err != nil {
			return fmt.Errorf("451 4.3.0 Message processing failed")
		}
		if mailpolicy.LargestAttachment(raw) > eff.MaxAttachmentBytes {
			return fmt.Errorf("552 5.3.4 An attachment is larger than your account may send (%d bytes maximum)", eff.MaxAttachmentBytes)
		}
	}
	return nil
}

// record counts a message accepted for sending. A failure to count is
// logged, not returned: the message is already accepted, and refusing it
// now would make the client send it again.
func (p *senderPolicies) record(ctx context.Context, user string, recipients int) {
	if err := p.counters.add(ctx, normalUser(user), recipients, p.now()); err != nil {
		p.log.Warn("sending counters not updated", "username", user, "error", err)
	}
}

// sendCounters keeps per-user sending counts in fixed windows.
type sendCounters interface {
	messages(ctx context.Context, user string, now time.Time) (int, error)
	recipients(ctx context.Context, user string, now time.Time) (int, error)
	add(ctx context.Context, user string, recipients int, now time.Time) error
}

func hourBucket(now time.Time) string { return strconv.FormatInt(now.Unix()/3600, 10) }
func dayBucket(now time.Time) string  { return now.UTC().Format("20060102") }

type memoryCounters struct {
	mu    sync.Mutex
	hours map[string]int // user|hour -> messages
	days  map[string]int // user|day -> recipients
}

func newMemoryCounters() *memoryCounters {
	return &memoryCounters{hours: map[string]int{}, days: map[string]int{}}
}

func (m *memoryCounters) messages(_ context.Context, user string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hours[user+"|"+hourBucket(now)], nil
}

func (m *memoryCounters) recipients(_ context.Context, user string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.days[user+"|"+dayBucket(now)], nil
}

func (m *memoryCounters) add(_ context.Context, user string, recipients int, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hour, day := hourBucket(now), dayBucket(now)
	// Old windows are dropped as new ones start, so the maps hold at most
	// the current hour and day.
	for k := range m.hours {
		if !strings.HasSuffix(k, "|"+hour) {
			delete(m.hours, k)
		}
	}
	for k := range m.days {
		if !strings.HasSuffix(k, "|"+day) {
			delete(m.days, k)
		}
	}
	m.hours[user+"|"+hour]++
	m.days[user+"|"+day] += recipients
	return nil
}

type valkeyCounters struct {
	client valkey.Client
	prefix string
}

func (v *valkeyCounters) get(ctx context.Context, key string) (int, error) {
	n, err := v.client.Do(ctx, v.client.B().Get().Key(key).Build()).AsInt64()
	if valkey.IsValkeyNil(err) {
		return 0, nil
	}
	return int(n), err
}

func (v *valkeyCounters) messages(ctx context.Context, user string, now time.Time) (int, error) {
	return v.get(ctx, v.prefix+"msg:"+user+":"+hourBucket(now))
}

func (v *valkeyCounters) recipients(ctx context.Context, user string, now time.Time) (int, error) {
	return v.get(ctx, v.prefix+"rcpt:"+user+":"+dayBucket(now))
}

func (v *valkeyCounters) add(ctx context.Context, user string, recipients int, now time.Time) error {
	msgKey := v.prefix + "msg:" + user + ":" + hourBucket(now)
	rcptKey := v.prefix + "rcpt:" + user + ":" + dayBucket(now)
	for _, r := range v.client.DoMulti(ctx,
		v.client.B().Incr().Key(msgKey).Build(),
		v.client.B().Expire().Key(msgKey).Seconds(2*3600).Build(),
		v.client.B().Incrby().Key(rcptKey).Increment(int64(recipients)).Build(),
		v.client.B().Expire().Key(rcptKey).Seconds(26*3600).Build(),
	) {
		if err := r.Error(); err != nil {
			return err
		}
	}
	return nil
}

// checkRecipientSize refuses, at RCPT, a local recipient whose class of
// service won't take a message of the size the client declared with SIZE.
// The mailbox enforces the same limit at delivery, but by then the MTA has
// accepted the message and can only bounce it; refusing here tells the
// sending server at once, with no bounce traffic. Only a definite answer
// refuses: an address the mailbox doesn't resolve to an account (a list, a
// catch-all) or a lookup that fails leaves the check to delivery.
func (p *senderPolicies) checkRecipientSize(ctx context.Context, rcpt string, declaredSize int64) error {
	if declaredSize <= 0 {
		return nil
	}
	eff, err := p.policy(ctx, rcpt)
	if err != nil {
		return nil
	}
	if eff.MaxMessageBytes > 0 && declaredSize > eff.MaxMessageBytes {
		return fmt.Errorf("552 5.3.4 <%s>: Message is larger than this recipient accepts (%d bytes maximum)", sanitizeEmailForHeader(rcpt), eff.MaxMessageBytes)
	}
	return nil
}
