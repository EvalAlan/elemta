package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EvalAlan/elemta/internal/metrics"
)

type stubDomainStats struct {
	stats []metrics.DomainStats
	err   error
}

func (s *stubDomainStats) GetMetrics(context.Context) (*DeliveryMetricsData, error) {
	return &DeliveryMetricsData{}, nil
}
func (s *stubDomainStats) GetHourlyStats(context.Context) ([]HourlyStatsData, error) { return nil, nil }
func (s *stubDomainStats) GetRecentErrors(context.Context, int64) ([]map[string]string, error) {
	return nil, nil
}
func (s *stubDomainStats) GetDomainStats(context.Context) ([]metrics.DomainStats, error) {
	return s.stats, s.err
}

func getDomainStats(t *testing.T, s *Server, query string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/stats/domains"+query, nil)
	rec := httptest.NewRecorder()
	s.handleDomainStats(rec, req)
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	return rec, body
}

// TestWorstDestinationsComeFirst. The reason to open this page is to find the
// destination going wrong, not to admire the ones that are fine.
func TestWorstDestinationsComeFirst(t *testing.T) {
	s := &Server{metricsStore: &stubDomainStats{stats: []metrics.DomainStats{
		{Domain: "fine.example", Delivered: 500},
		{Domain: "struggling.example", Delivered: 50, Deferred: 450},
		{Domain: "mixed.example", Delivered: 200, Deferred: 50, Bounced: 50},
	}}}

	_, body := getDomainStats(t, s, "")
	domains, _ := body["domains"].([]interface{})
	if len(domains) != 3 {
		t.Fatalf("got %d domains, want 3", len(domains))
	}
	first, _ := domains[0].(map[string]interface{})
	if first["domain"] != "struggling.example" {
		t.Errorf("first row is %v; the worst delivery rate should lead", first["domain"])
	}
}

// TestLowVolumeDestinationsDoNotLead: one deferral out of two is noise, and a
// page led by noise buries the real problem.
func TestLowVolumeDestinationsDoNotLead(t *testing.T) {
	s := &Server{metricsStore: &stubDomainStats{stats: []metrics.DomainStats{
		{Domain: "busy.example", Delivered: 300, Deferred: 200},
		{Domain: "onemessage.example", Deferred: 1},
	}}}

	_, body := getDomainStats(t, s, "")
	domains, _ := body["domains"].([]interface{})
	first, _ := domains[0].(map[string]interface{})
	if first["domain"] != "busy.example" {
		t.Errorf("first row is %v; a one-message destination outranked a real problem", first["domain"])
	}
}

func TestDeliveredPercentIsComputed(t *testing.T) {
	s := &Server{metricsStore: &stubDomainStats{stats: []metrics.DomainStats{
		{Domain: "a.example", Delivered: 75, Deferred: 25},
	}}}
	_, body := getDomainStats(t, s, "")
	domains, _ := body["domains"].([]interface{})
	row, _ := domains[0].(map[string]interface{})
	if row["delivered_percent"].(float64) != 75 {
		t.Errorf("delivered_percent = %v, want 75", row["delivered_percent"])
	}
	if row["total"].(float64) != 100 {
		t.Errorf("total = %v, want 100", row["total"])
	}
}

// TestNoMetricsStoreIsExplained. An empty table reads as "no mail has been
// sent"; the page has to be able to say why it is empty.
func TestNoMetricsStoreIsExplained(t *testing.T) {
	rec, body := getDomainStats(t, &Server{}, "")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; an unconfigured store is not an error", rec.Code)
	}
	if body["available"] != false || body["reason"] == nil {
		t.Errorf("no explanation given: %v", body)
	}
}

// TestUnreadableStoreIsNotAnEmptyTable, for the same reason.
func TestUnreadableStoreIsNotAnEmptyTable(t *testing.T) {
	s := &Server{metricsStore: &stubDomainStats{err: errors.New("connection refused")}}
	rec, body := getDomainStats(t, s, "")
	if rec.Code == http.StatusOK {
		t.Error("a store that could not be read looked like a successful empty report")
	}
	if body["available"] != false {
		t.Errorf("available = %v", body["available"])
	}
}

// TestTheReportSaysItIsNotComplete: the counters age out, so a page implying a
// full ledger would have somebody read "0 bounces" as good news.
func TestTheReportSaysItIsNotComplete(t *testing.T) {
	s := &Server{metricsStore: &stubDomainStats{stats: []metrics.DomainStats{{Domain: "a.example", Delivered: 1}}}}
	_, body := getDomainStats(t, s, "")
	if body["note"] == nil || body["note"] == "" {
		t.Error("the report does not say that it covers recent activity only")
	}
}

func TestDomainStatsRejectsNonsenseLimit(t *testing.T) {
	s := &Server{metricsStore: &stubDomainStats{}}
	for _, q := range []string{"?limit=0", "?limit=-1", "?limit=many"} {
		req := httptest.NewRequest(http.MethodGet, "/api/stats/domains"+q, nil)
		rec := httptest.NewRecorder()
		s.handleDomainStats(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit %q returned %d, want 400", q, rec.Code)
		}
	}
}
