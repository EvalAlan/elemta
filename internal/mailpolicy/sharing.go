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
