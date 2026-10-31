package mailpolicy

import (
	"context"
	"net/http"
	"net/url"
)

// Share is a member's access to an independently stored mailbox.
type Share struct {
	Mailbox string `json:"mailbox"`
	Member  string `json:"member"`
	CanSend bool   `json:"can_send"`
}

// CalendarShare is a member's access to someone's calendar. OwnerID lets the
// webmail lock the same object store the owner writes to.
type CalendarShare struct {
	Owner   string `json:"owner"`
	OwnerID string `json:"owner_id,omitempty"`
	Member  string `json:"member"`
	Level   string `json:"level"`
}

func (c *Client) CalendarShares(ctx context.Context, owner string) ([]CalendarShare, error) {
	out := []CalendarShare{}
	return out, c.do(ctx, http.MethodGet, "/v1/admin/accounts/"+seg(owner)+"/calendar-shares", nil, &out)
}

func (c *Client) GrantCalendar(ctx context.Context, owner, member, level string) (CalendarShare, error) {
	var out CalendarShare
	err := c.do(ctx, http.MethodPut, "/v1/admin/accounts/"+seg(owner)+"/calendar-shares/"+seg(member), map[string]string{"level": level}, &out)
	return out, err
}

func (c *Client) RevokeCalendar(ctx context.Context, owner, member string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/accounts/"+seg(owner)+"/calendar-shares/"+seg(member), nil, nil)
}

func (c *Client) Shares(ctx context.Context, mailbox string) ([]Share, error) {
	out := []Share{}
	return out, c.do(ctx, http.MethodGet, "/v1/admin/accounts/"+seg(mailbox)+"/shares", nil, &out)
}

func (c *Client) GrantShare(ctx context.Context, mailbox, member string, canSend bool) (Share, error) {
	var out Share
	err := c.do(ctx, http.MethodPut, "/v1/admin/accounts/"+seg(mailbox)+"/shares/"+seg(member), map[string]bool{"can_send": canSend}, &out)
	return out, err
}

func (c *Client) RevokeShare(ctx context.Context, mailbox, member string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/accounts/"+seg(mailbox)+"/shares/"+seg(member), nil, nil)
}

func (c *Client) ShareAccess(ctx context.Context, mailbox, member string, sending bool) (bool, error) {
	q := url.Values{"mailbox": {mailbox}, "member": {member}}
	if sending {
		q.Set("send", "true")
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/admin/share-access?"+q.Encode(), nil, &out)
	return out.Allowed, err
}
