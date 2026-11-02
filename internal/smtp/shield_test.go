package smtp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
)

// shieldAuthenticator accepts "right", and "app-password" as an app password.
type shieldAuthenticator struct{}

func (shieldAuthenticator) Authenticate(_ context.Context, _, password string) (bool, error) {
	return password == "right", nil
}
func (shieldAuthenticator) IsEnabled() bool  { return true }
func (shieldAuthenticator) IsRequired() bool { return false }
func (shieldAuthenticator) GetSupportedMethods() []AuthMethod {
	return []AuthMethod{AuthMethodPlain}
}
func (shieldAuthenticator) AuthenticateFrom(ctx context.Context, _, password string, _ net.IP) (bool, error) {
	if password == "app-password" {
		noteAppPassword(ctx)
		return true, nil
	}
	return password == "right", nil
}

// While an account is under attack, its right password from a network it
// hasn't used gets the same 535 as a wrong one; an app password doesn't.
func TestShieldedAccountOnSMTP(t *testing.T) {
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
	handler := func(ip string) *AuthHandler {
		ah := authHandlerFrom(t, ip, cfg, nil)
		ah.authenticator = shieldAuthenticator{}
		ah.abuse = engine
		return ah
	}
	err := handler("192.0.2.9").performAuthentication(ctx, "dana@example.com", "right", AuthMethodPlain)
	if err == nil || !strings.HasPrefix(err.Error(), "535") {
		t.Fatalf("right password from a new network during the attack: %v", err)
	}
	if handler("198.51.100.77").heldBack(ctx, "dana@example.com", false) {
		t.Fatal("the owner's network was held back")
	}
	if handler("192.0.2.9").heldBack(ctx, "dana@example.com", true) {
		t.Fatal("an app password was held back")
	}
	used := false
	if ok, _ := (shieldAuthenticator{}).AuthenticateFrom(watchAppPassword(ctx, &used), "dana@example.com", "app-password", nil); !ok || !used {
		t.Fatal("an app password's use wasn't noted")
	}
}
