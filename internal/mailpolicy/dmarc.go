package mailpolicy

// DMARC reports received about hosted domains.

import (
	"cmp"
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// DMARCAddress is where a domain's aggregate reports arrive, and how the last
// read of the reports already there went.
type DMARCAddress struct {
	Domain           string     `json:"domain"`
	Address          string     `json:"address"`
	BackfillStarted  *time.Time `json:"backfill_started,omitempty"`
	BackfillFinished *time.Time `json:"backfill_finished,omitempty"`
	BackfillRead     int64      `json:"backfill_read"`
	BackfillStored   int64      `json:"backfill_stored"`
	// BackfillUnindexed is mail the search index hadn't reached, which the
	// backfill therefore couldn't see.
	BackfillUnindexed int64  `json:"backfill_unindexed"`
	BackfillError     string `json:"backfill_error,omitempty"`
}

// DMARCDay is one reporter's count for one domain and day. Sender is the
// domain that sent the report: checked when Verified, only claimed when not.
// Org is always only claimed.
type DMARCDay struct {
	Domain       string `json:"domain"`
	PolicyDomain string `json:"policy_domain"`
	Day          string `json:"day"`
	Sender       string `json:"sender"`
	Org          string `json:"org"`
	Verified     bool   `json:"verified"`
	P            string `json:"p"`
	SP           string `json:"sp"`
	Pct          int    `json:"pct"`
	Reports      int64  `json:"reports"`
	Messages     int64  `json:"messages"`
	Aligned      int64  `json:"aligned"`
	Quarantined  int64  `json:"quarantined"`
	Rejected     int64  `json:"rejected"`
}

// DMARCSource is mail from one address, as reporters judged it.
type DMARCSource struct {
	Domain      string `json:"domain"`
	SourceIP    string `json:"source_ip"`
	HeaderFrom  string `json:"header_from"`
	Disposition string `json:"disposition"`
	DKIM        string `json:"dkim"`
	SPF         string `json:"spf"`
	DKIMDomain  string `json:"dkim_domain"`
	SPFDomain   string `json:"spf_domain"`
	Verified    bool   `json:"verified"`
	Messages    int64  `json:"messages"`
}

// DMARCSourceLimit is how many sources are returned, busiest first.
const DMARCSourceLimit = 2000

func dmarcQuery(domains []string, days int) string {
	return url.Values{"domain": domains, "days": {strconv.Itoa(days)}}.Encode()
}

// DMARCAddresses lists the report addresses. Every cell keeps them, and each
// reads the mail it holds, so their answers are folded into one per domain.
func (c *Client) DMARCAddresses(ctx context.Context) ([]DMARCAddress, error) {
	var all []DMARCAddress
	if err := c.do(ctx, http.MethodGet, "/v1/admin/dmarc/addresses", nil, &all); err != nil {
		return nil, err
	}
	out := []DMARCAddress{}
	for _, a := range all {
		i := slices.IndexFunc(out, func(o DMARCAddress) bool { return o.Domain == a.Domain })
		if i < 0 {
			out = append(out, a)
			continue
		}
		o := &out[i]
		o.BackfillRead += a.BackfillRead
		o.BackfillStored += a.BackfillStored
		o.BackfillUnindexed += a.BackfillUnindexed
		if o.BackfillError == "" {
			o.BackfillError = a.BackfillError
		}
		switch {
		case a.BackfillStarted == nil:
		case o.BackfillStarted == nil:
			o.BackfillStarted, o.BackfillFinished = a.BackfillStarted, a.BackfillFinished
		case o.BackfillFinished != nil && (a.BackfillFinished == nil || a.BackfillFinished.After(*o.BackfillFinished)):
			// Finished when the last cell has.
			o.BackfillFinished = a.BackfillFinished
		}
	}
	slices.SortFunc(out, func(a, b DMARCAddress) int { return cmp.Compare(a.Domain, b.Domain) })
	return out, nil
}

// SetDMARCAddress sets where a domain's reports arrive.
func (c *Client) SetDMARCAddress(ctx context.Context, domain, address string) (DMARCAddress, error) {
	var out DMARCAddress
	err := c.do(ctx, http.MethodPut, "/v1/admin/dmarc/addresses/"+seg(domain), map[string]string{"address": address}, &out)
	return out, err
}

// DeleteDMARCAddress stops reading a domain's reports; those already read
// stay until they age out.
func (c *Client) DeleteDMARCAddress(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/dmarc/addresses/"+seg(domain), nil, nil)
}

// StartDMARCBackfill starts reading the reports already in the mailbox.
func (c *Client) StartDMARCBackfill(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/dmarc/addresses/"+seg(domain)+"/backfill", nil, nil)
}

// DMARCSummary is the counts by day and reporter. No domains means all.
func (c *Client) DMARCSummary(ctx context.Context, domains []string, days int) ([]DMARCDay, error) {
	out := []DMARCDay{}
	if err := c.do(ctx, http.MethodGet, "/v1/admin/dmarc/summary?"+dmarcQuery(domains, days), nil, &out); err != nil {
		return nil, err
	}
	slices.SortStableFunc(out, func(a, b DMARCDay) int {
		return cmp.Or(cmp.Compare(a.Domain, b.Domain), cmp.Compare(a.Day, b.Day))
	})
	return out, nil
}

// DMARCSources is the busiest sources. No domains means all.
func (c *Client) DMARCSources(ctx context.Context, domains []string, days int) ([]DMARCSource, error) {
	var all []DMARCSource
	if err := c.do(ctx, http.MethodGet, "/v1/admin/dmarc/sources?"+dmarcQuery(domains, days), nil, &all); err != nil {
		return nil, err
	}
	// The same source can be in several cells.
	out, seen := []DMARCSource{}, map[DMARCSource]int{}
	for _, s := range all {
		key := s
		key.Messages = 0
		if i, ok := seen[key]; ok {
			out[i].Messages += s.Messages
			continue
		}
		seen[key] = len(out)
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b DMARCSource) int { return cmp.Compare(b.Messages, a.Messages) })
	return out[:min(len(out), DMARCSourceLimit)], nil
}
