package abuse

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// An account guessed at from many addresses can't be protected by blocking
// addresses, since each tries only a few times, and blocking the account would
// let anyone lock its owner out. What is left is where the owner signs in
// from. While an account is under attack, a correct password from a network
// it hasn't used is answered exactly like a wrong one, so the attacker can't
// tell a right guess from a wrong one, and the owner, signing in from home or
// work, carries on. App passwords and passkeys are too random to guess and
// are never held back.

const (
	keyTargets = "elemta:abuse:targets:"
	keyShield  = "elemta:abuse:shield:"
	keyKnown   = "elemta:abuse:known:"

	// knownMemory is how long a network stays familiar to an account, like
	// the countries kept for sign-in alerts.
	knownMemory = 90 * 24 * time.Hour
	// knownRefresh skips rewriting a network this service saw recently: mail
	// apps sign in every few minutes.
	knownRefresh = time.Hour

	// RefusedShielded counts correct passwords refused for coming from a
	// network the account hasn't used while it was under attack.
	RefusedShielded = "shielded"
	// AlertTargeted is raised when an account comes under attack.
	AlertTargeted = "targeted"
)

// noteTarget counts the networks failing against account, and shields the
// account once there are too many. The caller has checked the policy.
func (e *Engine) noteTarget(ctx context.Context, p Policy, network, service, account string, window time.Duration) {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" || len(account) > 320 {
		return
	}
	n := 0
	if client := e.valkey(); client != nil {
		key := keyTargets + account
		if client.Do(ctx, client.B().Sadd().Key(key).Member(network).Build()).Error() == nil {
			_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64(window.Seconds())).Build()).Error()
			if count, err := client.Do(ctx, client.B().Scard().Key(key).Build()).AsInt64(); err == nil {
				n = int(count)
			}
		}
	}
	if n == 0 {
		n = e.localTargets(account, network, window)
	}
	if n < p.AddressesPerAccount {
		return
	}
	detail := fmt.Sprintf("%d addresses failed to sign in within %d minutes. Until it stops, only networks the account has used before can sign in with its password.", n, p.WindowMinutes)
	if p.Mode != ModeEnforce {
		if n == p.AddressesPerAccount {
			e.record(ctx, Event{Action: "would-shield", Network: account, Service: service, Detail: fmt.Sprintf("%d addresses failed within %d minutes", n, p.WindowMinutes)})
		}
		return
	}
	// Renewed by every failure past the limit, so it lasts as long as the
	// attack does and one window after.
	shielded := e.setShield(ctx, account, window)
	if !shielded {
		e.raise(ctx, Alert{Time: time.Now().UTC(), Account: account, Kind: AlertTargeted, Address: network, Service: service, Detail: detail})
		e.log.Warn("Account under attack from many addresses; unfamiliar networks held back", "account", account, "addresses", n)
	}
}

// setShield marks account as under attack for window, and reports whether it
// already was.
func (e *Engine) setShield(ctx context.Context, account string, window time.Duration) bool {
	if client := e.valkey(); client != nil {
		key := keyShield + account
		existed, err := client.Do(ctx, client.B().Exists().Key(key).Build()).AsInt64()
		if err == nil {
			_ = client.Do(ctx, client.B().Set().Key(key).Value("1").Ex(window).Build()).Error()
			return existed > 0
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	if e.seen.shields == nil {
		e.seen.shields = map[string]time.Time{}
	}
	until, ok := e.seen.shields[account]
	e.seen.shields[account] = time.Now().Add(window)
	return ok && time.Now().Before(until)
}

func (e *Engine) localTargets(account, network string, window time.Duration) int {
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	now := time.Now()
	if e.seen.targets == nil {
		e.seen.targets = map[string]*spraySet{}
	}
	s, ok := e.seen.targets[account]
	if !ok || now.After(s.reset) {
		s = &spraySet{accounts: map[string]bool{}, reset: now.Add(window)}
		e.seen.targets[account] = s
	}
	s.accounts[network] = true
	return len(s.accounts)
}

// Shielded reports whether a sign-in to account from addr, with a correct
// password, must be refused because the account is under attack and addr is
// on a network it hasn't signed in from. Callers check it after the password,
// leave out app passwords and passkeys, and answer exactly as for a wrong
// password. Anything it can't tell, it lets through: this mustn't become a
// way to lock owners out.
func (e *Engine) Shielded(ctx context.Context, addr, account string) bool {
	if e == nil {
		return false
	}
	p := e.Policy()
	ip := hostIP(addr)
	account = strings.ToLower(strings.TrimSpace(account))
	if p.Mode != ModeEnforce || p.AddressesPerAccount < 1 || ip == nil || ip.IsPrivate() || ip.IsLoopback() || account == "" || e.Exempt(addr) {
		return false
	}
	subnet := Subnet(Network(ip.String()))
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	shielded, known, history := false, false, false
	if client := e.valkey(); client != nil {
		n, err := client.Do(ctx, client.B().Exists().Key(keyShield+account).Build()).AsInt64()
		if err != nil {
			return false
		}
		if shielded = n > 0; !shielded {
			return false
		}
		if known, err = client.Do(ctx, client.B().Sismember().Key(keyKnown+account).Member(subnet).Build()).AsBool(); err != nil {
			return false
		}
		size, err := client.Do(ctx, client.B().Scard().Key(keyKnown+account).Build()).AsInt64()
		if err != nil {
			return false
		}
		history = size > 0
	} else {
		e.seen.mu.Lock()
		until, ok := e.seen.shields[account]
		shielded = ok && time.Now().Before(until)
		networks := e.seen.known[account]
		_, known = networks[subnet]
		history = len(networks) > 0
		e.seen.mu.Unlock()
	}
	// An account with no history has nothing to compare against, and
	// refusing everyone would be the lockout this is built to avoid.
	if !shielded || known || !history {
		return false
	}
	e.Refused(RefusedShielded)
	e.log.Info("Correct password from an unfamiliar network refused while the account is under attack", "account", account, "network", subnet)
	return true
}

// rememberNetwork keeps the network a successful sign-in came from, for
// Shielded to recognise later.
func (e *Engine) rememberNetwork(ctx context.Context, account string, ip string) {
	subnet := Subnet(Network(ip))
	if subnet == "" {
		return
	}
	now := time.Now()
	e.seen.mu.Lock()
	if e.seen.known == nil {
		e.seen.known = map[string]map[string]time.Time{}
	}
	networks := e.seen.known[account]
	if networks == nil {
		if len(e.seen.known) > 100000 {
			e.seen.known = map[string]map[string]time.Time{}
		}
		networks = map[string]time.Time{}
		e.seen.known[account] = networks
	}
	last, recent := networks[subnet]
	networks[subnet] = now
	e.seen.mu.Unlock()
	if recent && now.Sub(last) < knownRefresh {
		return
	}
	if client := e.valkey(); client != nil {
		ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
		defer cancel()
		key := keyKnown + account
		if client.Do(ctx, client.B().Sadd().Key(key).Member(subnet).Build()).Error() == nil {
			_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64(knownMemory.Seconds())).Build()).Error()
		}
	}
}
