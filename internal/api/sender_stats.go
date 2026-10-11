package api

import (
	"context"
	"math"
	"net/http"
	"strconv"

	"github.com/EvalAlan/elemta/internal/metrics"
)

// SenderStatsStore is implemented by metrics stores that keep sender
// reputation telemetry. Optional, so stores (and test stubs) that do not keep
// it need not change.
type SenderStatsStore interface {
	GetSenderStats(ctx context.Context, days int) ([]metrics.SenderStats, error)
}

// GetSenderStats passes through to the Valkey store.
func (a *valkeyMetricsAdapter) GetSenderStats(ctx context.Context, days int) ([]metrics.SenderStats, error) {
	return a.store.GetSenderStats(ctx, days)
}

// SenderStatsData is one pool, source address or provider over the window.
type SenderStatsData struct {
	metrics.SenderStats
	Attempts int64 `json:"attempts"`
	// Rates are percentages to two decimals. Complaint thresholds are set in
	// tenths of a percent, so a whole-number rate would read 0 for a sender
	// that is already over the line.
	ComplaintRate float64 `json:"complaint_rate_percent"`
	BounceRate    float64 `json:"bounce_rate_percent"`
	DeferralRate  float64 `json:"deferral_rate_percent"`
	ThrottleRate  float64 `json:"throttle_rate_percent"`
	// Status is "ok", "warning", "critical" or "low_volume"; Reasons says
	// which threshold put it there.
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

// Thresholds for the status column.
//
// The complaint thresholds are Google's and Yahoo's published bulk-sender
// requirements (February 2024): keep the spam rate below 0.1%, and never
// reach 0.3%. The bounce thresholds are not published by anyone; they are
// the common industry rule of thumb that a list bouncing more than a couple
// of percent has a hygiene problem, and are labelled as such in the reasons.
const (
	complaintWarnPercent     = 0.1
	complaintCriticalPercent = 0.3
	bounceWarnPercent        = 2.0
	bounceCriticalPercent    = 5.0
	// senderStatsMinVolume is the delivered count below which rates are not
	// judged: one complaint in fifty messages is 2%, and says nothing.
	senderStatsMinVolume = 100
)

// handleSenderStats reports outcomes and complaint rates per sending pool,
// source address and mailbox provider.
func (s *Server) handleSenderStats(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{"senders": []SenderStatsData{}}

	store, ok := s.metricsStore.(SenderStatsStore)
	if s.metricsStore == nil || !ok {
		response["available"] = false
		response["reason"] = "Sender statistics need the Valkey metrics store, which is not configured"
		writeJSON(w, response)
		return
	}

	days := 1
	if raw := r.URL.Query().Get("days"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > metrics.SenderRetentionDays {
			http.Error(w, "days must be between 1 and "+strconv.Itoa(metrics.SenderRetentionDays), http.StatusBadRequest)
			return
		}
		days = parsed
	}

	stats, err := store.GetSenderStats(r.Context(), days)
	if err != nil {
		response["available"] = false
		response["reason"] = "Sender statistics could not be read: " + err.Error()
		writeJSONStatus(w, http.StatusBadGateway, response)
		return
	}

	out := make([]SenderStatsData, 0, len(stats))
	for _, st := range stats {
		out = append(out, judgeSender(st))
	}

	response["available"] = true
	response["days"] = days
	response["senders"] = out
	// Said on the response because the absence would otherwise read as good
	// news: Gmail sends no feedback-loop reports, so a Gmail complaint rate
	// of zero here means "not reported", and Google Postmaster Tools is
	// where that number lives.
	response["note"] = "Complaints are counted from feedback-loop (ARF) reports. Gmail does not send these; use Google Postmaster Tools for Gmail's spam rate. Days are UTC."
	writeJSON(w, response)
}

func judgeSender(st metrics.SenderStats) SenderStatsData {
	d := SenderStatsData{SenderStats: st, Attempts: st.Attempts(), Status: "ok"}
	d.ComplaintRate = percent(st.Complained, st.Delivered)
	d.BounceRate = percent(st.Bounced, d.Attempts)
	d.DeferralRate = percent(st.Deferred, d.Attempts)
	d.ThrottleRate = percent(st.Throttled, d.Attempts)

	if st.Delivered < senderStatsMinVolume {
		d.Status = "low_volume"
		return d
	}
	raise := func(status, reason string) {
		if status == "critical" || d.Status == "ok" {
			d.Status = status
		}
		d.Reasons = append(d.Reasons, reason)
	}
	switch {
	case d.ComplaintRate >= complaintCriticalPercent:
		raise("critical", "complaint rate at or above 0.3%, the Gmail and Yahoo limit")
	case d.ComplaintRate >= complaintWarnPercent:
		raise("warning", "complaint rate at or above 0.1%, the Gmail and Yahoo target")
	}
	switch {
	case d.BounceRate >= bounceCriticalPercent:
		raise("critical", "bounce rate at or above 5% (rule of thumb, not a provider limit)")
	case d.BounceRate >= bounceWarnPercent:
		raise("warning", "bounce rate at or above 2% (rule of thumb, not a provider limit)")
	}
	if st.Throttled > 0 {
		raise("warning", "provider throttled this sender")
	}
	return d
}

// percent is part/whole as a percentage rounded to two decimals.
func percent(part, whole int64) float64 {
	if whole <= 0 {
		return 0
	}
	return math.Round(float64(part)/float64(whole)*10000) / 100
}
