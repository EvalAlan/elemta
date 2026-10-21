package smtp

// App passwords and the "require app passwords" setting at SMTP AUTH.
//
// Accounts, two-step verification and app passwords belong to the mailbox
// service (internal/mailbox/security.go). Its IMAP and POP3 listeners refuse
// an account password when the user requires app passwords; without the same
// rule here, a stolen password could still send mail as the user through
// submission. So, when [auth] mailbox_security_url is set:
//
//   - An account password that the directory accepts is then refused if the
//     user requires app passwords, unless the client is in
//     app_password_exempt_networks. That list holds the webmail, which signs
//     in with the account password after its own second step.
//   - A password the directory refuses is tried as an app password.
//
// Both answers come from the mailbox service's internal API, asked with the
// user's own credentials, so Elemta holds no privilege there. If the API
// can't be reached, the login fails: whether the user requires app passwords
// is then unknown, and accepting would skip the protection they chose.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// clientAuthenticator is an Authenticator that also weighs where the client
// connects from. AuthHandler prefers it when the authenticator offers it.
type clientAuthenticator interface {
	AuthenticateFrom(ctx context.Context, username, password string, client net.IP) (bool, error)
}

type mailboxSecurity struct {
	base   string
	exempt []*net.IPNet
	client *http.Client
}

type securityCheckResult struct {
	Kind        string `json:"kind"` // "password", "app", or "admin"
	AppRequired bool   `json:"app_required"`
	// Protocols is the class of service's protocol switches; a missing
	// entry, or a mailbox service that predates them, allows.
	Protocols map[string]bool `json:"protocols"`
}

var errSecurityRefused = errors.New("mailbox security: credentials refused")

// newMailboxSecurity reads [auth] mailbox_security_url and
// app_password_exempt_networks, or ELEMTA_AUTH_MAILBOX_SECURITY_URL and
// ELEMTA_AUTH_APP_PASSWORD_EXEMPT (comma-separated), which win so a deployment
// can turn this on without rewriting its configuration. nil means off.
func newMailboxSecurity(config *AuthConfig) (*mailboxSecurity, error) {
	base := config.MailboxSecurityURL
	if v := os.Getenv("ELEMTA_AUTH_MAILBOX_SECURITY_URL"); v != "" {
		base = v
	}
	if base == "" {
		return nil, nil
	}
	networks := config.AppPasswordExemptNetworks
	if v := os.Getenv("ELEMTA_AUTH_APP_PASSWORD_EXEMPT"); v != "" {
		networks = strings.Split(v, ",")
	}
	m := &mailboxSecurity{base: strings.TrimSuffix(base, "/"), client: &http.Client{Timeout: 5 * time.Second}}
	for _, cidr := range networks {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("[auth] app_password_exempt_networks: %w", err)
		}
		m.exempt = append(m.exempt, n)
	}
	return m, nil
}

func (m *mailboxSecurity) isExempt(ip net.IP) bool {
	for _, n := range m.exempt {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *mailboxSecurity) check(ctx context.Context, username, password string) (securityCheckResult, error) {
	var out securityCheckResult
	// #nosec G704 -- the base URL is the operator's [auth] mailbox_security_url; the path is fixed
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.base+"/v1/security/check", nil)
	if err != nil {
		return out, err
	}
	req.SetBasicAuth(username, password)
	resp, err := m.client.Do(req) // #nosec G704 -- request built above from operator configuration only
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out)
		return out, err
	case http.StatusUnauthorized:
		return out, errSecurityRefused
	default:
		return out, fmt.Errorf("mailbox security: %s", resp.Status)
	}
}

// AuthenticateFrom applies the app-password rules described above on top of
// the directory check.
func (a *SMTPAuthenticator) AuthenticateFrom(ctx context.Context, username, password string, client net.IP) (bool, error) {
	ok, err := a.Authenticate(ctx, username, password)
	if a.security == nil || !a.config.Enabled {
		return ok, err
	}
	if err != nil {
		return false, err
	}
	if ok && a.security.isExempt(client) {
		return true, nil
	}
	check, err := a.security.check(ctx, username, password)
	switch {
	case errors.Is(err, errSecurityRefused):
		return false, nil
	case err != nil:
		a.logger.Warn("mailbox security check unavailable; refusing login", "username", username, "error", err)
		return false, err
	}
	if check.Kind == "admin" {
		return false, nil
	}
	if allowed, set := check.Protocols[mailpolicy.Submission]; set && !allowed {
		a.logger.Info("SMTP submission refused by class of service", "username", username, "client", client.String())
		return false, nil
	}
	if check.Kind == "app" {
		// Accepted by the mailbox service as an app password. The directory
		// refused it, which is expected: it only knows the account password.
		return true, nil
	}
	if !ok {
		return false, nil
	}
	if check.AppRequired {
		a.logger.Info("account password refused; app password required", "username", username, "client", client.String())
		return false, nil
	}
	return true, nil
}
