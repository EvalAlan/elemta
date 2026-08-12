package api

import (
	"net/http"
	"sort"
	"strconv"
)

// DomainStatsData is one destination's recent record.
type DomainStatsData struct {
	Domain    string `json:"domain"`
	Delivered int64  `json:"delivered"`
	Deferred  int64  `json:"deferred"`
	Bounced   int64  `json:"bounced"`
	Total     int64  `json:"total"`
	// DeliveredPercent is rounded to a whole number. Deliverability is judged
	// in tens of percent, and a figure to two decimal places invites reading
	// precision into a count of a few hundred messages that is not there.
	DeliveredPercent int `json:"delivered_percent"`
}

// handleDomainStats reports how each destination has been treating our mail.
//
// Aggregate delivery numbers say whether the queue is moving. They cannot say
// that one receiver has been deferring everything for an hour while the rest of
// the world is fine, which is the question behind most "is our mail getting
// through?" investigations — and the one that decides whether to change
// something or simply wait.
func (s *Server) handleDomainStats(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{"domains": []DomainStatsData{}}

	if s.metricsStore == nil {
		// No metrics store is a deployment without Valkey, not a fault. Saying
		// so lets the page explain itself instead of showing an empty table
		// that reads as "no mail has been sent".
		response["available"] = false
		response["reason"] = "Per-destination statistics need the Valkey metrics store, which is not configured"
		writeJSON(w, response)
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "limit must be a positive number", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	stats, err := s.metricsStore.GetDomainStats(r.Context())
	if err != nil {
		response["available"] = false
		response["reason"] = "Per-destination statistics could not be read: " + err.Error()
		writeJSONStatus(w, http.StatusBadGateway, response)
		return
	}

	out := make([]DomainStatsData, 0, len(stats))
	for _, stat := range stats {
		total := stat.Delivered + stat.Deferred + stat.Bounced
		if total == 0 {
			continue
		}
		out = append(out, DomainStatsData{
			Domain:           stat.Domain,
			Delivered:        stat.Delivered,
			Deferred:         stat.Deferred,
			Bounced:          stat.Bounced,
			Total:            total,
			DeliveredPercent: int(float64(stat.Delivered) / float64(total) * 100),
		})
	}

	// Worst delivery rate first among comparable volumes: the reason to open
	// this page is to find the destination that is going wrong, not to admire
	// the ones that are fine. Destinations with almost no traffic sort last
	// because one deferral out of two is noise, not a problem.
	sort.Slice(out, func(i, j int) bool {
		iNoise, jNoise := out[i].Total < domainStatsNoiseFloor, out[j].Total < domainStatsNoiseFloor
		if iNoise != jNoise {
			return jNoise
		}
		if out[i].DeliveredPercent != out[j].DeliveredPercent {
			return out[i].DeliveredPercent < out[j].DeliveredPercent
		}
		return out[i].Total > out[j].Total
	})

	if len(out) > limit {
		out = out[:limit]
	}

	response["available"] = true
	response["domains"] = out
	response["count"] = len(out)
	// These counters describe recent activity rather than all time: the store
	// is bounded and destinations age out. A page that implies a complete
	// ledger would have somebody read "0 bounces" as good news when it means
	// nothing was recorded.
	response["note"] = "Recent activity per destination, not a complete history"
	writeJSON(w, response)
}

// domainStatsNoiseFloor is the volume below which a delivery rate says more
// about chance than about the destination.
const domainStatsNoiseFloor = 10
