package webmail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A shared mailbox login ("member|mailbox") must not go to the security
// API, which knows plain accounts only and would refuse it.
func TestCoordinatedDialerOpensSharedMailbox(t *testing.T) {
	var checks atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks.Add(1)
		if user, _, _ := r.BasicAuth(); strings.Contains(user, "|") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"account_id":"acct-1","kind":"password"}`))
	}))
	t.Cleanup(api.Close)
	dial := coordinatedObjectDialer(&objectCoordinator{}, newSecurityClient(api.URL), func(context.Context, string, string) (Mailstore, error) {
		return &fakeStore{}, nil
	})
	st, err := dial(context.Background(), "dana@example.com|support@example.com", "pw")
	if err != nil {
		t.Fatalf("shared mailbox: %v", err)
	}
	_ = st.Close()
	if checks.Load() != 0 {
		t.Errorf("the shared mailbox login was sent to the security API")
	}
	st, err = dial(context.Background(), "dana@example.com", "pw")
	if err != nil {
		t.Fatalf("own mailbox: %v", err)
	}
	if owner := st.(coordinatedMailstore).owner; owner != "acct-1" || checks.Load() != 1 {
		t.Errorf("own mailbox owner = %q after %d checks", owner, checks.Load())
	}
}
