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

// Resource kinds and how they book.
const (
	ResourceRoom      = "room"
	ResourceEquipment = "equipment"
	BookingAuto       = "auto"
	BookingManual     = "manual"
)

// Resource is an account people book rather than a person: a meeting room or a
// piece of shared equipment.
type Resource struct {
	Address  string `json:"address"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Location string `json:"location,omitempty"`
	Capacity int    `json:"capacity,omitempty"`
	// Booking is auto, first come first served, or manual, when a delegate of
	// the account answers.
	Booking string `json:"booking"`
}

// Resources lists resources, those of a domain if one is given.
func (c *Client) Resources(ctx context.Context, domain string) ([]Resource, error) {
	out := []Resource{}
	path := "/v1/admin/resources"
	if domain != "" {
		path += "?domain=" + seg(domain)
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// PutResource makes an account bookable, or changes its settings.
func (c *Client) PutResource(ctx context.Context, address string, r Resource) (Resource, error) {
	var out Resource
	err := c.do(ctx, http.MethodPut, "/v1/admin/accounts/"+seg(address)+"/resource", r, &out)
	return out, err
}

// DeleteResource makes an account an ordinary one again.
func (c *Client) DeleteResource(ctx context.Context, address string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/accounts/"+seg(address)+"/resource", nil, nil)
}
