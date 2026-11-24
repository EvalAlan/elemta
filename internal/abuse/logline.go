package abuse

import (
	"context"
	"log/slog"
	"net/netip"
)

// eventMessages are the log lines' words for each recorded action. An action
// missing here, such as a new kind of sign-in alert, is logged as
// "Abuse: <action>".
var eventMessages = map[string]string{
	"blocked":        "Address blocked",
	"unblocked":      "Address unblocked",
	"would-block":    "Address would be blocked (logging only)",
	"held":           "Account's outside mail put on hold",
	"released":       "Account's outside mail released",
	"would-hold":     "Account's outside mail would be put on hold (logging only)",
	"would-shield":   "Account under attack; would hold back unfamiliar networks (logging only)",
	AlertTravel:      "Sign-in alert: impossible travel",
	AlertNewCountry:  "Sign-in alert: new country",
	AlertTargeted:    "Sign-in alert: account under attack from many addresses",
	"shield-refused": "Correct password from an unfamiliar network refused while the account is under attack",
	"rule-refused":   "Refused by a rule",
	"would-rule":     "Would be refused by a rule (logging only)",
	"would-limit":    "Connection limit reached (logging only)",
}

// warnActions are the ones that stop someone; the rest are informational.
var warnActions = map[string]bool{
	"blocked": true, "held": true, AlertTravel: true, AlertNewCountry: true, AlertTargeted: true,
}

// attrs are the fields every abuse line carries, so the logs and anything
// they are shipped to can find, count and place them: event_type "abuse",
// the action, and the target as the right kind of field. An address or
// network also goes in client_ip (a network's first address), which log
// shipping indexes as source.ip for GeoIP and ASN; an account goes in
// username, indexed as user.name.
func attrs(action, target string) []any {
	a := []any{"event_type", "abuse", "abuse_action", action}
	if target == "" {
		return a
	}
	if where := addressAttrs(target); where != nil {
		return append(a, where...)
	}
	return append(a, "username", target)
}

// addressAttrs are the network and client_ip fields for an address or
// network, or nil for anything else.
func addressAttrs(target string) []any {
	if p, err := netip.ParsePrefix(target); err == nil {
		return []any{"network", p.Masked().String(), "client_ip", p.Masked().Addr().String()}
	}
	if ip, err := netip.ParseAddr(target); err == nil {
		return []any{"network", ip.Unmap().String(), "client_ip", ip.Unmap().String()}
	}
	return nil
}

// logEvent writes ev to the service's log. record keeps it for the console;
// this line is what reaches the log file, the Logs tab and log shipping.
func (e *Engine) logEvent(ctx context.Context, ev Event) {
	msg, ok := eventMessages[ev.Action]
	if !ok {
		msg = "Abuse: " + ev.Action
	}
	level := slog.LevelInfo
	if warnActions[ev.Action] {
		level = slog.LevelWarn
	}
	args := attrs(ev.Action, ev.Network)
	if ev.Account != "" {
		args = append(args, "username", ev.Account)
	}
	// The engine's "service" is the protocol the attempt came over; "admin"
	// marks a console action, which isn't one.
	if ev.Service != "" && ev.Service != "admin" {
		args = append(args, "protocol", ev.Service)
	}
	if ev.Detail != "" {
		args = append(args, "detail", ev.Detail)
	}
	if ev.By != "" {
		args = append(args, "by", ev.By)
	}
	e.log.Log(ctx, level, msg, args...)
}
