package mailpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// The admin API is served by the mailbox service on its internal health
// port, to internal networks only, and every request carries a shared
// bearer token. Both barriers matter: the token is what separates the
// administration tools from everything else on the internal network (the
// webmail, the MTA's user-level checks), which may reach that port too.

// TokenEnv names the environment variable holding the admin token, on the
// mailbox service and on every client.
const TokenEnv = "ELEMTA_MAILBOX_ADMIN_TOKEN" // #nosec G101 -- the variable's name, not a credential

// URLEnv overrides the admin API's base URL, which otherwise comes from the
// caller's configuration ([auth] mailbox_security_url, the same port).
const URLEnv = "ELEMTA_MAILBOX_ADMIN_URL"

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("conflict")
	ErrUnavailable = errors.New("mailbox administration is not configured")
)

// Client calls the mailbox admin API.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient returns a client for the admin API at base, authenticating with
// token. Either empty means administration isn't configured.
func NewClient(base, token string) (*Client, error) {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" || token == "" {
		return nil, ErrUnavailable
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("mailbox admin URL %q is not an http(s) URL", base)
	}
	return &Client{base: base, token: token, http: &http.Client{Timeout: 30 * time.Second}}, nil
}

// FromEnv builds a client from URLEnv (or fallback, the configured mailbox
// security URL) and TokenEnv.
func FromEnv(fallback string) (*Client, error) {
	base := os.Getenv(URLEnv)
	if base == "" {
		base = fallback
	}
	return NewClient(base, os.Getenv(TokenEnv))
}

// APIError is a refusal from the admin API, with its message.
type APIError struct {
	Status  int
	Message string
	kind    error
}

func (e *APIError) Error() string { return e.Message }
func (e *APIError) Unwrap() error { return e.kind }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	// #nosec G704 -- the base URL is operator configuration; paths are fixed with escaped segments
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req) // #nosec G704 -- request built above from operator configuration
	if err != nil {
		return fmt.Errorf("mailbox admin API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var problem struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &problem)
		if problem.Error == "" {
			problem.Error = resp.Status
		}
		apiErr := &APIError{Status: resp.StatusCode, Message: problem.Error}
		switch resp.StatusCode {
		case http.StatusNotFound:
			apiErr.kind = ErrNotFound
		case http.StatusConflict:
			apiErr.kind = ErrConflict
		case http.StatusBadRequest:
			apiErr.kind = ErrInvalid
		}
		return apiErr
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func seg(s string) string { return url.PathEscape(s) }

// Classes lists the classes of service.
func (c *Client) Classes(ctx context.Context) ([]Class, error) {
	var out []Class
	return out, c.do(ctx, http.MethodGet, "/v1/admin/classes", nil, &out)
}

// Class returns one class of service.
func (c *Client) Class(ctx context.Context, name string) (Class, error) {
	var out Class
	return out, c.do(ctx, http.MethodGet, "/v1/admin/classes/"+seg(name), nil, &out)
}

// PutClass creates or replaces a class of service.
func (c *Client) PutClass(ctx context.Context, class Class) (Class, error) {
	var out Class
	return out, c.do(ctx, http.MethodPut, "/v1/admin/classes/"+seg(class.Name), class, &out)
}

// DeleteClass removes a class no account or domain uses.
func (c *Client) DeleteClass(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/classes/"+seg(name), nil, nil)
}

// Domains lists the domains that name a class.
func (c *Client) Domains(ctx context.Context) ([]DomainPolicy, error) {
	var out []DomainPolicy
	return out, c.do(ctx, http.MethodGet, "/v1/admin/domains", nil, &out)
}

// SetDomain sets the class a domain's accounts use by default; an empty
// class clears it.
func (c *Client) SetDomain(ctx context.Context, p DomainPolicy) (DomainPolicy, error) {
	var out DomainPolicy
	return out, c.do(ctx, http.MethodPut, "/v1/admin/domains/"+seg(p.Domain), p, &out)
}

// AccountView is an account's stored policy and what it works out to.
type AccountView struct {
	Policy    AccountPolicy `json:"policy"`
	Effective Effective     `json:"effective"`
}

// Account returns an account's stored policy and its effective policy.
func (c *Client) Account(ctx context.Context, address string) (AccountView, error) {
	var out AccountView
	return out, c.do(ctx, http.MethodGet, "/v1/admin/accounts/"+seg(address)+"/policy", nil, &out)
}

// PutAccount replaces an account's class and overrides.
func (c *Client) PutAccount(ctx context.Context, p AccountPolicy) (AccountView, error) {
	var out AccountView
	return out, c.do(ctx, http.MethodPut, "/v1/admin/accounts/"+seg(p.Address)+"/policy", p, &out)
}

// Effective returns the effective policy for an address or login name, for
// enforcement. It resolves aliases to their account.
func (c *Client) Effective(ctx context.Context, address string) (Effective, error) {
	var out Effective
	return out, c.do(ctx, http.MethodGet, "/v1/admin/effective?address="+url.QueryEscape(address), nil, &out)
}

// PurgeResult reports what a purge removed.
type PurgeResult struct {
	Address  string `json:"address"`
	Accounts int    `json:"accounts"`
	Messages int    `json:"messages"`
	Folders  int    `json:"folders"`
}

// Purge removes every piece of mailbox data held for an address: folders,
// messages, filters, security settings and policy. The account must already
// be gone from the directory.
func (c *Client) Purge(ctx context.Context, address string) (PurgeResult, error) {
	var out PurgeResult
	return out, c.do(ctx, http.MethodPost, "/v1/admin/accounts/"+seg(address)+"/purge", nil, &out)
}

// Routes lists domains with an alias target or a catch-all.
func (c *Client) Routes(ctx context.Context) ([]DomainRoute, error) {
	var out []DomainRoute
	return out, c.do(ctx, http.MethodGet, "/v1/admin/routes", nil, &out)
}

// SetRoute replaces a domain's alias target and catch-all; both empty
// removes the route.
func (c *Client) SetRoute(ctx context.Context, r DomainRoute) (DomainRoute, error) {
	var out DomainRoute
	return out, c.do(ctx, http.MethodPut, "/v1/admin/routes/"+seg(r.Domain), r, &out)
}

// Lists lists the distribution lists, without their members.
func (c *Client) Lists(ctx context.Context) ([]List, error) {
	var out []List
	return out, c.do(ctx, http.MethodGet, "/v1/admin/lists", nil, &out)
}

// List returns a distribution list with its members.
func (c *Client) List(ctx context.Context, address string) (List, error) {
	var out List
	return out, c.do(ctx, http.MethodGet, "/v1/admin/lists/"+seg(address), nil, &out)
}

// PutList creates a list or replaces its settings and members.
func (c *Client) PutList(ctx context.Context, l List) (List, error) {
	var out List
	return out, c.do(ctx, http.MethodPut, "/v1/admin/lists/"+seg(l.Address), l, &out)
}

// ChangeMembers adds and removes members without replacing the rest.
func (c *Client) ChangeMembers(ctx context.Context, address string, add, remove []string) (List, error) {
	var out List
	body := map[string][]string{"add": add, "remove": remove}
	return out, c.do(ctx, http.MethodPost, "/v1/admin/lists/"+seg(address)+"/members", body, &out)
}

// DeleteList removes a distribution list.
func (c *Client) DeleteList(ctx context.Context, address string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/lists/"+seg(address), nil, nil)
}

// Address says what owns an address: an account, an alias, a list, or
// nothing.
func (c *Client) Address(ctx context.Context, address string) (AddressInfo, error) {
	var out AddressInfo
	return out, c.do(ctx, http.MethodGet, "/v1/admin/addresses/"+seg(address), nil, &out)
}
