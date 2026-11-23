package smtp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/logging"
)

// downAuthenticator can't reach its directory.
type downAuthenticator struct{ shieldAuthenticator }

func (downAuthenticator) AuthenticateFrom(context.Context, string, string, net.IP) (bool, error) {
	return false, errors.New("directory unreachable")
}

// A refused SMTP sign-in says why in failure_reason, as IMAP, POP3 and the
// webmail's do. It used to be logged empty.
func TestSMTPAuthFailuresSayWhy(t *testing.T) {
	ctx := context.Background()
	p := abuse.DefaultPolicy()
	p.AddressesPerAccount = 3
	engine := abuse.New("test", "", nil)
	engine.Own(p)
	engine.RecordSignIn(ctx, "198.51.100.20:4000", "smtp", "dana@example.com")
	for i := 1; i <= 3; i++ {
		engine.Failure(ctx, fmt.Sprintf("203.0.%d.1:5000", i), "smtp", "dana@example.com")
	}
	cfg := &Config{Auth: &AuthConfig{Enabled: true, AllowPlaintextAuth: true}}

	for _, tc := range []struct {
		name, user, password, want string
		auth                       Authenticator
	}{
		{"wrong password", "sam@example.com", "wrong", "credentials", shieldAuthenticator{}},
		{"right password held back by the shield", "dana@example.com", "right", "account_shielded", shieldAuthenticator{}},
		{"directory down", "sam@example.com", "right", "unavailable", downAuthenticator{}},
		{"malformed", "", "", "invalid_request", shieldAuthenticator{}},
	} {
		var buf bytes.Buffer
		ah := authHandlerFrom(t, "192.0.2.9", cfg, nil)
		ah.authenticator = tc.auth
		ah.abuse = engine
		ah.msgLogger = logging.NewMessageLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
		if err := ah.performAuthentication(ctx, tc.user, tc.password, AuthMethodPlain); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
		var found bool
		for _, l := range strings.Split(buf.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) != nil || m["event_type"] != "authentication" {
				continue
			}
			found = true
			if m["success"] != false || m["failure_reason"] != tc.want {
				t.Errorf("%s: success=%v failure_reason=%v, want false %q", tc.name, m["success"], m["failure_reason"], tc.want)
			}
		}
		if !found {
			t.Errorf("%s: no authentication line:\n%s", tc.name, buf.String())
		}
	}
}
