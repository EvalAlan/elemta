package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EvalAlan/elemta/internal/metrics"
)

type stubSenderStats struct {
	stubDomainStats
	stats   []metrics.SenderStats
	gotDays int
}

func (s *stubSenderStats) GetSenderStats(_ context.Context, days int) ([]metrics.SenderStats, error) {
	s.gotDays = days
	return s.stats, nil
}

func getSenderStats(t *testing.T, s *Server, query string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/stats/senders"+query, nil)
	rec := httptest.NewRecorder()
	s.handleSenderStats(rec, req)
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestJudgeSenderAgainstProviderThresholds(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   metrics.SenderStats
		want string
	}{
		{"clean", metrics.SenderStats{Delivered: 10000, Complained: 5}, "ok"},                      // 0.05%
		{"over the 0.1% target", metrics.SenderStats{Delivered: 10000, Complained: 15}, "warning"}, // 0.15%
		{"at the 0.3% limit", metrics.SenderStats{Delivered: 10000, Complained: 30}, "critical"},   // 0.30%
		{"bouncing", metrics.SenderStats{Delivered: 1000, Bounced: 60}, "critical"},                // 5.66%
		{"throttled", metrics.SenderStats{Delivered: 1000, Deferred: 10, Throttled: 10}, "warning"},
		{"warning does not mask critical", metrics.SenderStats{Delivered: 10000, Complained: 40, Bounced: 300}, "critical"},
		{"too little to judge", metrics.SenderStats{Delivered: 50, Complained: 5}, "low_volume"},
	} {
		got := judgeSender(tc.st)
		if got.Status != tc.want {
			t.Errorf("%s: status %q (%v), want %q", tc.name, got.Status, got.Reasons, tc.want)
		}
	}

	d := judgeSender(metrics.SenderStats{Delivered: 10000, Complained: 15})
	if d.ComplaintRate != 0.15 {
		t.Errorf("complaint rate = %v, want 0.15 (two decimals; thresholds are in tenths)", d.ComplaintRate)
	}
}

func TestSenderStatsEndpoint(t *testing.T) {
	stub := &stubSenderStats{stats: []metrics.SenderStats{
		{Dimension: "pool", Key: "bulk", Delivered: 1000, Complained: 4},
	}}
	s := &Server{metricsStore: stub}

	rec, body := getSenderStats(t, s, "?days=7")
	if rec.Code != http.StatusOK || body["available"] != true || stub.gotDays != 7 {
		t.Fatalf("code %d body %v days %d", rec.Code, body, stub.gotDays)
	}
	senders, _ := body["senders"].([]interface{})
	row, _ := senders[0].(map[string]interface{})
	if row["key"] != "bulk" || row["status"] != "critical" || row["complaint_rate_percent"] != 0.4 {
		t.Errorf("row = %v", row)
	}
	if body["note"] == nil {
		t.Error("the response must say that Gmail sends no feedback-loop reports")
	}

	for _, bad := range []string{"?days=0", "?days=8", "?days=x"} {
		if rec, _ := getSenderStats(t, s, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400", bad, rec.Code)
		}
	}

	// A store without sender telemetry says so instead of an empty table.
	_, body = getSenderStats(t, &Server{metricsStore: &stubDomainStats{}}, "")
	if body["available"] != false || body["reason"] == nil {
		t.Errorf("unavailable body = %v", body)
	}
}
