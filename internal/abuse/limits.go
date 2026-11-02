package abuse

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Limits on volume rather than on failure: how much mail one address may send
// in, and how much one account may send out. A hacked account is the case the
// second is for. Its password works, so nothing else here notices it, and by
// the time a blocklist does the server's reputation is gone.

const (
	keyInbound  = "elemta:abuse:in:"
	keyDomain   = "elemta:abuse:domain:"
	keyOutbound = "elemta:abuse:out:"
	keySpray    = "elemta:abuse:spray:"
	keyHolds    = "elemta:abuse:holds"

	// RefusedMessages counts mail turned away for its address's volume.
	RefusedMessages = "messages"
	// RefusedDomain counts mail turned away for its sender domain's volume.
	RefusedDomain = "domain"
	// RefusedHeld counts mail an account on hold tried to send.
	RefusedHeld = "held"
)

// Hold stops an account sending outside the server until an administrator
// releases it. It doesn't expire: a hacked account that resumed by itself would
// carry on where it stopped.
type Hold struct {
	Account    string    `json:"account"`
	Reason     string    `json:"reason"`
	Recipients int       `json:"recipients"`
	Created    time.Time `json:"created"`
}

// InboundMessage counts a message from addr and reports whether it may go on.
// Callers leave out signed-in users and allowed relays: this is for mail from
// outside.
func (e *Engine) InboundMessage(ctx context.Context, addr string) bool {
	if e == nil {
		return true
	}
	p := e.Policy()
	network := Network(addr)
	if p.Mode == ModeOff || p.MessagesPerAddressPerHour < 1 || network == "" || e.Exempt(addr) {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	if e.count(ctx, keyInbound+network, "in:"+network, time.Hour) <= p.MessagesPerAddressPerHour {
		return true
	}
	e.Refused(RefusedMessages)
	return p.Mode != ModeEnforce
}

// InboundDomain counts a message whose sender is in domain, from outside, and
// reports whether it may go on. Callers leave out signed-in users and allowed
// relays, as for InboundMessage.
func (e *Engine) InboundDomain(ctx context.Context, addr, sender string) bool {
	if e == nil {
		return true
	}
	p := e.Policy()
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(sender)), "@")
	// A bounce has no sender, and isn't anyone's to count.
	if p.Mode == ModeOff || p.MessagesPerDomainPerHour < 1 || !ok || domain == "" || len(domain) > 253 || e.Exempt(addr) {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	if e.count(ctx, keyDomain+domain, "domain:"+domain, time.Hour) <= p.MessagesPerDomainPerHour {
		return true
	}
	e.Refused(RefusedDomain)
	return p.Mode != ModeEnforce
}

// OutboundRecipient counts one recipient outside the server for account, and
// reports whether the account may send to it. Passing the limit puts the
// account on hold.
func (e *Engine) OutboundRecipient(ctx context.Context, account string) bool {
	if e == nil {
		return true
	}
	p := e.Policy()
	account = strings.ToLower(strings.TrimSpace(account))
	if p.Mode == ModeOff || account == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	if _, held := e.held(ctx, account); held {
		e.Refused(RefusedHeld)
		return p.Mode != ModeEnforce
	}
	if p.OutboundRecipientsPerHour < 1 {
		return true
	}
	n := e.count(ctx, keyOutbound+account, "out:"+account, time.Hour)
	if n <= p.OutboundRecipientsPerHour {
		return true
	}
	reason := fmt.Sprintf("%d recipients outside the server in an hour", n)
	if p.Mode != ModeEnforce {
		if n == p.OutboundRecipientsPerHour+1 {
			e.record(ctx, Event{Action: "would-hold", Network: account, Service: "smtp", Detail: reason})
		}
		return true
	}
	h := Hold{Account: account, Reason: reason, Recipients: n, Created: time.Now().UTC()}
	e.placeHold(ctx, h)
	e.record(ctx, Event{Action: "held", Network: account, Service: "smtp", Detail: reason + "; sending stopped until released"})
	e.log.Warn("Account's outside mail put on hold", "account", account, "recipients", n)
	e.Refused(RefusedHeld)
	return false
}

func (e *Engine) held(ctx context.Context, account string) (Hold, bool) {
	if client := e.valkey(); client != nil {
		raw, err := client.Do(ctx, client.B().Hget().Key(keyHolds).Field(account).Build()).ToString()
		if err == nil {
			var h Hold
			if json.Unmarshal([]byte(raw), &h) == nil {
				return h, true
			}
		}
		// No hold in Valkey is an answer, and may be a release made on
		// another replica: only an outage falls back to this service's own.
		if valkey.IsValkeyNil(err) {
			return Hold{}, false
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	h, ok := e.seen.holds[account]
	return h, ok
}

func (e *Engine) placeHold(ctx context.Context, h Hold) {
	e.seen.mu.Lock()
	if e.seen.holds == nil {
		e.seen.holds = map[string]Hold{}
	}
	e.seen.holds[h.Account] = h
	e.seen.mu.Unlock()
	if client := e.valkey(); client != nil {
		if raw, err := json.Marshal(h); err == nil {
			_ = client.Do(ctx, client.B().Hset().Key(keyHolds).FieldValue().FieldValue(h.Account, string(raw)).Build()).Error()
		}
	}
}

// Holds lists the accounts on hold, newest first.
func (e *Engine) Holds(ctx context.Context) []Hold {
	out := []Hold{}
	if e == nil {
		return out
	}
	if client := e.valkey(); client != nil {
		rows, err := client.Do(ctx, client.B().Hgetall().Key(keyHolds).Build()).AsStrMap()
		if err == nil {
			for _, raw := range rows {
				var h Hold
				if json.Unmarshal([]byte(raw), &h) == nil {
					out = append(out, h)
				}
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
			return out
		}
	}
	e.seen.mu.Lock()
	for _, h := range e.seen.holds {
		out = append(out, h)
	}
	e.seen.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Release lets a held account send again, and starts its count afresh so it
// isn't held again by the mail that put it on hold.
func (e *Engine) Release(ctx context.Context, account, by string) error {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" {
		return fmt.Errorf("name the account to release")
	}
	e.seen.mu.Lock()
	delete(e.seen.holds, account)
	delete(e.seen.counts, "out:"+account)
	e.seen.mu.Unlock()
	if client := e.valkey(); client != nil {
		if err := client.Do(ctx, client.B().Hdel().Key(keyHolds).Field(account).Build()).Error(); err != nil {
			return err
		}
		_ = client.Do(ctx, client.B().Del().Key(keyOutbound+account).Build()).Error()
	}
	e.record(ctx, Event{Action: "released", Network: account, Service: "smtp", By: by})
	return nil
}

// spray counts the accounts one address has failed against, and reports how
// many: one address trying many accounts is guessing common passwords, which a
// count of failures alone is slow to catch when it tries each only once.
func (e *Engine) spray(ctx context.Context, network, account string, window time.Duration) int {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" || len(account) > 320 {
		return 0
	}
	if client := e.valkey(); client != nil {
		key := keySpray + network
		if err := client.Do(ctx, client.B().Sadd().Key(key).Member(account).Build()).Error(); err == nil {
			_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64(window.Seconds())).Build()).Error()
			if n, err := client.Do(ctx, client.B().Scard().Key(key).Build()).AsInt64(); err == nil {
				return int(n)
			}
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	now := time.Now()
	if e.seen.sprays == nil {
		e.seen.sprays = map[string]*spraySet{}
	}
	s, ok := e.seen.sprays[network]
	if !ok || now.After(s.reset) {
		s = &spraySet{accounts: map[string]bool{}, reset: now.Add(window)}
		e.seen.sprays[network] = s
	}
	s.accounts[account] = true
	return len(s.accounts)
}

type spraySet struct {
	accounts map[string]bool
	reset    time.Time
}
