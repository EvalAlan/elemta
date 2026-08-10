package api

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Editing a plugin's settings, as distinct from turning it on and off.
//
// The settings forms in the web UI were previously write-only in the worst
// sense: they rendered the current values, let the operator change them, and
// had nowhere to send them — the update endpoint read `enabled` and ignored
// everything else. A form that discards what is typed into it is worse than no
// form, because the operator leaves believing the setting took.
//
// Values are checked here rather than at startup. The alternative is a config
// file the SMTP server refuses to load: the change looks accepted, and mail
// stops at the next restart with the cause several hours behind.

// applyPluginConfig validates a settings payload and copies it onto the live
// configuration. Absent keys are left as they are, so the UI may send a partial
// update; a key that is present but the wrong type or out of range is an error
// naming the field, since silently coercing it is how a scan limit becomes zero.
//
// Each plugin is edited through a copy that is only committed once the whole
// payload validates. Applying field by field would leave a rejected update
// half-written into the running configuration.
func (s *Server) applyPluginConfig(plugin string, cfg map[string]interface{}) error {
	r := &cfgReader{cfg: cfg}

	switch plugin {
	case "clamav":
		if s.mainConfig.Antivirus == nil {
			s.mainConfig.Antivirus = &ScannerStatus{}
		}
		next := *s.mainConfig.Antivirus
		r.str("address", &next.Address, validateHostPort)
		r.intv("timeout", &next.Timeout, 1, 3600)
		r.int64v("scan_limit", &next.ScanLimit, 0, 1<<40)
		r.boolv("reject_on_failure", &next.RejectOnFailure)
		if err := r.err(); err != nil {
			return err
		}
		*s.mainConfig.Antivirus = next

	case "rspamd":
		if s.mainConfig.Antispam == nil {
			s.mainConfig.Antispam = &ScannerStatus{}
		}
		next := *s.mainConfig.Antispam
		r.str("address", &next.Address, validateHTTPURL)
		r.intv("timeout", &next.Timeout, 1, 3600)
		r.int64v("scan_limit", &next.ScanLimit, 0, 1<<40)
		r.floatv("threshold", &next.Threshold, 0, 1000)
		r.boolv("reject_on_spam", &next.RejectOnSpam)
		if err := r.err(); err != nil {
			return err
		}
		*s.mainConfig.Antispam = next

	case "access_control":
		if s.mainConfig.AccessControl == nil {
			s.mainConfig.AccessControl = &AccessControlStatus{}
		}
		next := *s.mainConfig.AccessControl
		r.list("allow_ips", &next.AllowIPs, validateAccessAddress)
		r.list("deny_ips", &next.DenyIPs, validateAccessAddress)
		r.list("allow_domains", &next.AllowDomains, validateAccessDomain)
		r.list("deny_domains", &next.DenyDomains, validateAccessDomain)
		if err := r.err(); err != nil {
			return err
		}
		*s.mainConfig.AccessControl = next

	case "rbl":
		if s.mainConfig.RBL == nil {
			s.mainConfig.RBL = &RBLStatus{}
		}
		next := *s.mainConfig.RBL
		r.list("zones", &next.Zones, validateRBLZone)
		r.list("skip_ips", &next.SkipIPs, validateAccessAddress)
		r.boolv("reject", &next.Reject)
		r.intv("timeout", &next.Timeout, 1, 60)
		r.intv("cache_ttl", &next.CacheTTL, 60, 86400)
		// The cache must stay bounded: keyed by peer address and unbounded it
		// is a memory exhaustion vector, so there is no "0 means unlimited".
		r.intv("cache_size", &next.CacheSize, 100, 1_000_000)
		if err := r.err(); err != nil {
			return err
		}
		// Enabled with nothing to query is a filter the operator believes is
		// protecting them, and it is also what the server refuses to start
		// with — so it is caught here rather than at the next restart.
		if next.Enabled && len(next.Zones) == 0 {
			return errors.New("zones: at least one blocklist is required while the plugin is enabled")
		}
		*s.mainConfig.RBL = next

	case "mass_mailer":
		if s.mainConfig.MassMailer == nil {
			s.mainConfig.MassMailer = &MassMailerStatus{}
		}
		next := *s.mainConfig.MassMailer
		// An unbounded default rate is the setting nobody notices until a
		// campaign has swamped the queue, so zero is not accepted here.
		r.intv("default_rate_per_minute", &next.DefaultRatePerMinute, 1, 1_000_000)
		r.intv("max_recipients", &next.MaxRecipients, 0, 100_000_000)
		if err := r.err(); err != nil {
			return err
		}
		*s.mainConfig.MassMailer = next

	case "rate_limiter":
		// The rate limiter has its own endpoint and its own form, which predate
		// the generic panels. Routing it through here as well would give two
		// paths writing the same settings with different validation.
		return errors.New("rate limiter settings are edited through the rate limiting panel")

	default:
		return fmt.Errorf("plugin %q has no editable settings", plugin)
	}

	return nil
}

// cfgReader pulls typed values out of a decoded JSON object, collecting every
// problem instead of stopping at the first. An operator fixing one field at a
// time through a form that reports one error per attempt gives up.
type cfgReader struct {
	cfg      map[string]interface{}
	problems []string
}

func (r *cfgReader) err() error {
	if len(r.problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(r.problems, "; "))
}

func (r *cfgReader) bad(format string, args ...interface{}) {
	r.problems = append(r.problems, fmt.Sprintf(format, args...))
}

func (r *cfgReader) str(key string, dst *string, validate func(string) error) {
	raw, ok := r.cfg[key]
	if !ok {
		return
	}
	v, ok := raw.(string)
	if !ok {
		r.bad("%s must be text", key)
		return
	}
	v = strings.TrimSpace(v)
	if validate != nil {
		if err := validate(v); err != nil {
			r.bad("%s: %v", key, err)
			return
		}
	}
	*dst = v
}

// number reads a JSON number. Every JSON number arrives as a float64, so the
// integer forms have to check for a fractional part themselves rather than
// truncating: a timeout of 0.5 silently becoming 0 means no timeout at all.
func (r *cfgReader) number(key string) (float64, bool) {
	raw, ok := r.cfg[key]
	if !ok {
		return 0, false
	}
	v, ok := raw.(float64)
	if !ok {
		r.bad("%s must be a number", key)
		return 0, false
	}
	return v, true
}

func (r *cfgReader) intv(key string, dst *int, min, max int) {
	v, ok := r.number(key)
	if !ok {
		return
	}
	if v != float64(int64(v)) {
		r.bad("%s must be a whole number", key)
		return
	}
	if int64(v) < int64(min) || int64(v) > int64(max) {
		r.bad("%s must be between %d and %d", key, min, max)
		return
	}
	*dst = int(v)
}

func (r *cfgReader) int64v(key string, dst *int64, min, max int64) {
	v, ok := r.number(key)
	if !ok {
		return
	}
	if v != float64(int64(v)) {
		r.bad("%s must be a whole number", key)
		return
	}
	if int64(v) < min || int64(v) > max {
		r.bad("%s must be between %d and %d", key, min, max)
		return
	}
	*dst = int64(v)
}

func (r *cfgReader) floatv(key string, dst *float64, min, max float64) {
	v, ok := r.number(key)
	if !ok {
		return
	}
	if v < min || v > max {
		r.bad("%s must be between %g and %g", key, min, max)
		return
	}
	*dst = v
}

func (r *cfgReader) boolv(key string, dst *bool) {
	raw, ok := r.cfg[key]
	if !ok {
		return
	}
	v, ok := raw.(bool)
	if !ok {
		r.bad("%s must be true or false", key)
		return
	}
	*dst = v
}

// list reads a list of strings, dropping blanks and validating what remains.
// An empty list is a meaningful value — it clears the rule — so it is kept
// rather than treated as "no change".
func (r *cfgReader) list(key string, dst *[]string, validate func(string) error) {
	raw, ok := r.cfg[key]
	if !ok {
		return
	}
	items, ok := raw.([]interface{})
	if !ok {
		r.bad("%s must be a list", key)
		return
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			r.bad("%s must be a list of text entries", key)
			return
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if validate != nil {
			if err := validate(s); err != nil {
				r.bad("%s: %v", key, err)
				continue
			}
		}
		out = append(out, s)
	}
	*dst = out
}

// validateHostPort accepts what net.Dial accepts. clamd is reached over a raw
// socket, so a URL here connects to nothing — and with reject_on_failure off,
// which is the default, every message would then pass unscanned in silence.
func validateHostPort(v string) error {
	if v == "" {
		return errors.New("an address is required")
	}
	if strings.Contains(v, "://") {
		return fmt.Errorf("%q looks like a URL; this scanner needs host:port", v)
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("%q is not host:port", v)
	}
	if host == "" || port == "" {
		return fmt.Errorf("%q is missing a host or a port", v)
	}
	return nil
}

// validateHTTPURL accepts the base URL of an HTTP scanner. The path "/checkv2"
// is appended to it, so a trailing slash or a stray path is worth catching now
// rather than as a 404 on every message.
func validateHTTPURL(v string) error {
	if v == "" {
		return errors.New("an address is required")
	}
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("%q is not a URL", v)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q must start with http:// or https://", v)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", v)
	}
	if strings.TrimSuffix(u.Path, "/") != "" {
		return fmt.Errorf("%q must be a base URL, without a path", v)
	}
	if strings.HasSuffix(v, "/") {
		return fmt.Errorf("%q must not end with a slash", v)
	}
	return nil
}

// validateAccessAddress mirrors the parsing the SMTP server does at startup.
// It has to: a rule the server cannot parse is a fatal startup error, so
// accepting one here trades a visible form error for a server that will not
// come back up.
func validateAccessAddress(v string) error {
	if strings.Contains(v, "/") {
		if _, _, err := net.ParseCIDR(v); err != nil {
			return fmt.Errorf("%q is not a valid network", v)
		}
		return nil
	}
	if net.ParseIP(v) == nil {
		return fmt.Errorf("%q is not a valid address or network", v)
	}
	return nil
}

// validateRBLZone rejects what a blocklist zone is not. A URL or a bare label
// produces a query that can never match, so the plugin would look configured
// and filter nothing.
func validateRBLZone(v string) error {
	if strings.Contains(v, "://") {
		return fmt.Errorf("%q is a URL; a blocklist zone is a domain name", v)
	}
	if strings.ContainsAny(v, " \t/:") {
		return fmt.Errorf("%q is not a domain name", v)
	}
	if !strings.Contains(strings.Trim(v, "."), ".") {
		return fmt.Errorf("%q is not a domain name", v)
	}
	return nil
}

// validateAccessDomain rejects the shapes that look like they will work and do
// not: an address where a domain belongs matches nothing, because the rule is
// compared against the sender's domain alone.
func validateAccessDomain(v string) error {
	if strings.ContainsAny(v, " \t") {
		return fmt.Errorf("%q must not contain spaces", v)
	}
	if strings.Contains(v, "@") {
		return fmt.Errorf("%q is an address; list the domain on its own", v)
	}
	if strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
		return fmt.Errorf("%q must not start or end with a dot", v)
	}
	if !strings.Contains(v, ".") {
		// A bare label is either a TLD, which is refused when matching so that
		// one entry cannot block the internet, or a typo. Either way the rule
		// would never fire, and a rule that never fires is worse than an error.
		return fmt.Errorf("%q is not a domain", v)
	}
	return nil
}
