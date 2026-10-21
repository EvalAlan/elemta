package mailpolicy

import (
	"context"
	"net/http"
	"time"
)

// AdminAccess is a one-account, one-hour credential for webmail's internal
// IMAP listener. The token must stay out of URLs and logs.
type AdminAccess struct {
	Address string    `json:"address"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

func (c *Client) AdminAccess(ctx context.Context, address, actor, client string) (AdminAccess, error) {
	var out AdminAccess
	err := c.do(ctx, http.MethodPost, "/v1/admin/accounts/"+seg(address)+"/access", map[string]string{
		"actor": actor, "client": client,
	}, &out)
	return out, err
}
