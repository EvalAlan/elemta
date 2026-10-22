package smtp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/EvalAlan/elemta/internal/datasource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The directory knows only the account password; the fake mailbox security
// API also knows one app password, and whether this user requires them.
func appPasswordAuthenticator(t *testing.T, required *atomic.Bool, apiUp *atomic.Bool, submissionOff ...*atomic.Bool) *SMTPAuthenticator {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !apiUp.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		user, pw, _ := r.BasicAuth()
		kind := map[string]string{"account-pw": "password", "app-pw": "app", "admin-token": "admin"}[pw]
		if r.URL.Path != "/v1/security/check" || user != "dana@example.com" || kind == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		out := map[string]any{"kind": kind, "app_required": required.Load()}
		if len(submissionOff) > 0 && submissionOff[0].Load() {
			out["protocols"] = map[string]bool{"submission": false, "imap": true}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(api.Close)

	oldFactory := newAuthDataSource
	t.Cleanup(func() { newAuthDataSource = oldFactory })
	newAuthDataSource = func(datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{authenticateFn: func(_ context.Context, u, p string) (bool, error) {
			return u == "dana@example.com" && p == "account-pw", nil
		}}, nil
	}
	auth, err := NewAuthenticator(&AuthConfig{
		Enabled: true, DataSourceName: "ldap", DataSourceHost: "ldap.internal",
		MailboxSecurityURL:        api.URL,
		AppPasswordExemptNetworks: []string{"10.253.53.250"},
	})
	require.NoError(t, err)
	return auth
}

func TestSubmissionAppPasswords(t *testing.T) {
	var required, apiUp atomic.Bool
	apiUp.Store(true)
	a := appPasswordAuthenticator(t, &required, &apiUp)
	ctx := context.Background()
	phone := net.ParseIP("203.0.113.9")
	webmail := net.ParseIP("10.253.53.250")
	login := func(pw string, from net.IP) bool {
		t.Helper()
		ok, _ := a.AuthenticateFrom(ctx, "dana@example.com", pw, from)
		return ok
	}

	assert.True(t, login("account-pw", phone), "account password before the requirement")
	assert.True(t, login("app-pw", phone), "app password, which the directory doesn't know")
	assert.False(t, login("wrong", phone), "wrong password")
	assert.False(t, login("admin-token", phone), "administrator mailbox token cannot submit")
	assert.False(t, login("admin-token", webmail), "administrator mailbox token cannot submit from webmail")

	required.Store(true)
	assert.False(t, login("account-pw", phone), "account password once app passwords are required")
	assert.True(t, login("app-pw", phone), "app password with the requirement")
	assert.True(t, login("account-pw", webmail), "the webmail, which has asked for its own second step")
	assert.False(t, login("wrong", webmail), "the exemption doesn't skip the password itself")

	// Not knowing whether the user requires app passwords refuses the login.
	apiUp.Store(false)
	assert.False(t, login("account-pw", phone), "account password with the API down")
	assert.True(t, login("account-pw", webmail), "the webmail doesn't depend on the API")
}

func TestSubmissionAppPasswordsConfig(t *testing.T) {
	m, err := newMailboxSecurity(&AuthConfig{})
	require.NoError(t, err)
	assert.Nil(t, m, "off unless a URL is configured")

	t.Setenv("ELEMTA_AUTH_MAILBOX_SECURITY_URL", "http://mailbox:8080/")
	t.Setenv("ELEMTA_AUTH_APP_PASSWORD_EXEMPT", "10.0.0.5, 192.168.1.0/24,fd00::1")
	m, err = newMailboxSecurity(&AuthConfig{MailboxSecurityURL: "http://ignored"})
	require.NoError(t, err)
	assert.Equal(t, "http://mailbox:8080", m.base)
	assert.True(t, m.isExempt(net.ParseIP("10.0.0.5")))
	assert.False(t, m.isExempt(net.ParseIP("10.0.0.6")))
	assert.True(t, m.isExempt(net.ParseIP("192.168.1.77")))
	assert.True(t, m.isExempt(net.ParseIP("fd00::1")))
	assert.False(t, m.isExempt(nil))

	t.Setenv("ELEMTA_AUTH_APP_PASSWORD_EXEMPT", "not-an-address")
	_, err = newMailboxSecurity(&AuthConfig{})
	assert.Error(t, err)
}

// TestSubmissionSwitch pins the class of service's submission switch: a mail
// app is refused even with the right password, while the webmail, which
// sends on the user's behalf from an exempt network, still can.
func TestSubmissionSwitch(t *testing.T) {
	var required, apiUp, off atomic.Bool
	apiUp.Store(true)
	a := appPasswordAuthenticator(t, &required, &apiUp, &off)
	ctx := context.Background()
	phone, webmail := net.ParseIP("203.0.113.9"), net.ParseIP("10.253.53.250")
	ok, _ := a.AuthenticateFrom(ctx, "dana@example.com", "account-pw", phone)
	assert.True(t, ok, "submission allowed by default")
	off.Store(true)
	ok, _ = a.AuthenticateFrom(ctx, "dana@example.com", "account-pw", phone)
	assert.False(t, ok, "submission turned off by the class of service")
	ok, _ = a.AuthenticateFrom(ctx, "dana@example.com", "app-pw", phone)
	assert.False(t, ok, "an app password doesn't get round it")
	ok, _ = a.AuthenticateFrom(ctx, "dana@example.com", "account-pw", webmail)
	assert.True(t, ok, "the webmail still sends")
}

// TestWebmailSubmissionPort pins that a session on the webmail's own
// submission port may use the account password when the account requires
// app passwords, from any address, and that other sessions may not.
func TestWebmailSubmissionPort(t *testing.T) {
	var required, apiUp, off atomic.Bool
	apiUp.Store(true)
	required.Store(true)
	a := appPasswordAuthenticator(t, &required, &apiUp, &off)
	pod := net.ParseIP("10.42.7.19") // any address: a webmail pod or replica
	ok, _ := a.AuthenticateFrom(context.Background(), "dana@example.com", "account-pw", pod)
	assert.False(t, ok, "account password refused on the ordinary submission port")
	ok, _ = a.AuthenticateFrom(withWebmailSubmission(context.Background()), "dana@example.com", "account-pw", pod)
	assert.True(t, ok, "account password accepted on the webmail's port")
	ok, _ = a.AuthenticateFrom(withWebmailSubmission(context.Background()), "dana@example.com", "wrong", pod)
	assert.False(t, ok, "the webmail's port still checks the password")
}
