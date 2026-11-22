package mailpolicy

// What an administrator needs to help one account: how full it is, how it
// signs in, and which app passwords could still be using it.

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// AppPassword describes an app password. The secret is never kept, so there
// is none to show.
type AppPassword struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

// AccountSecurity is an account's storage and sign-in state.
type AccountSecurity struct {
	UsedBytes    int64         `json:"used_bytes"`
	QuotaBytes   int64         `json:"quota_bytes"` // in effect; 0 is unlimited
	TOTP         bool          `json:"totp"`
	RecoveryLeft int           `json:"recovery_left"`
	Passkeys     int           `json:"passkeys"`
	AppRequired  bool          `json:"app_required"` // the owner's own choice
	AppPasswords []AppPassword `json:"app_passwords"`
}

// Usage is the storage held under one address.
type Usage struct {
	Address   string `json:"address"`
	UsedBytes int64  `json:"used_bytes"`
}

// Usage lists the storage used by every mailbox.
func (c *Client) Usage(ctx context.Context) ([]Usage, error) {
	out := []Usage{}
	return out, c.do(ctx, http.MethodGet, "/v1/admin/usage", nil, &out)
}

// AccountSecurity reads an account's storage and sign-in state.
func (c *Client) AccountSecurity(ctx context.Context, address string) (AccountSecurity, error) {
	var out AccountSecurity
	return out, c.do(ctx, http.MethodGet, "/v1/admin/accounts/"+seg(address)+"/security", nil, &out)
}

// RevokeAppPassword removes one of an account's app passwords.
func (c *Client) RevokeAppPassword(ctx context.Context, address string, id int64) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/accounts/"+seg(address)+"/app-passwords/"+strconv.FormatInt(id, 10), nil, nil)
}

// RevokeAppPasswords removes all of them and says how many there were.
func (c *Client) RevokeAppPasswords(ctx context.Context, address string) (int64, error) {
	var out struct {
		Revoked int64 `json:"revoked"`
	}
	err := c.do(ctx, http.MethodDelete, "/v1/admin/accounts/"+seg(address)+"/app-passwords", nil, &out)
	return out.Revoked, err
}
