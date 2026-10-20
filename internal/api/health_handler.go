package api

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/EvalAlan/elemta/internal/queue"
	"github.com/EvalAlan/elemta/internal/version"
)

// HealthStats represents server health statistics
type HealthStats struct {
	Status                    string         `json:"status"`
	Uptime                    int64          `json:"uptime"`           // seconds
	UptimeFormatted           string         `json:"uptime_formatted"` // human readable
	StartedAt                 time.Time      `json:"started_at"`
	GoVersion                 string         `json:"go_version"`
	NumGoroutines             int            `json:"num_goroutines"`
	NumCPU                    int            `json:"num_cpu"`
	Memory                    MemoryStats    `json:"memory"`
	Queue                     QueueHealth    `json:"queue"`
	SMTP                      SMTPHealth     `json:"smtp"`
	Throughput                ThroughputInfo `json:"throughput"`
	ServerVersion             string         `json:"server_version"`
	ConfiguredAddr            string         `json:"configured_addr"`
	AuthEnabled               bool           `json:"auth_enabled"`
	FailedQueueRetentionHours int            `json:"failed_queue_retention_hours"`
}

// MemoryStats represents memory usage statistics
type MemoryStats struct {
	Alloc        uint64  `json:"alloc"`          // bytes allocated and in use
	TotalAlloc   uint64  `json:"total_alloc"`    // bytes allocated total
	Sys          uint64  `json:"sys"`            // bytes obtained from system
	HeapAlloc    uint64  `json:"heap_alloc"`     // heap bytes allocated
	HeapSys      uint64  `json:"heap_sys"`       // heap bytes from system
	HeapInuse    uint64  `json:"heap_inuse"`     // heap bytes in use
	HeapIdle     uint64  `json:"heap_idle"`      // heap bytes idle
	HeapReleased uint64  `json:"heap_released"`  // heap bytes released
	StackInuse   uint64  `json:"stack_inuse"`    // stack bytes in use
	NumGC        uint32  `json:"num_gc"`         // number of GC cycles
	LastGC       int64   `json:"last_gc"`        // last GC time (unix nano)
	GCPauseTotal uint64  `json:"gc_pause_total"` // total GC pause time (ns)
	AllocMB      float64 `json:"alloc_mb"`       // allocated in MB
	SysMB        float64 `json:"sys_mb"`         // system memory in MB
}

// QueueHealth represents queue health information
type QueueHealth struct {
	TotalMessages            int    `json:"total_messages"`
	ActiveCount              int    `json:"active_count"`
	DeferredCount            int    `json:"deferred_count"`
	HoldCount                int    `json:"hold_count"`
	FailedCount              int    `json:"failed_count"`
	ProcessorActive          bool   `json:"processor_active"`
	OldestActiveAgeSeconds   int64  `json:"oldest_active_age_seconds"`
	OldestDeferredAgeSeconds int64  `json:"oldest_deferred_age_seconds"`
	OldestFailedAgeSeconds   int64  `json:"oldest_failed_age_seconds"`
	OldestActiveAge          string `json:"oldest_active_age"`
	OldestDeferredAge        string `json:"oldest_deferred_age"`
	OldestFailedAge          string `json:"oldest_failed_age"`
}

// SMTPHealth represents SMTP server health
type SMTPHealth struct {
	Listening         bool   `json:"listening"`
	ListenAddr        string `json:"listen_addr"`
	TLSEnabled        bool   `json:"tls_enabled"`
	StartTLSEnabled   bool   `json:"starttls_enabled"`
	AuthEnabled       bool   `json:"auth_enabled"`
	ActiveConnections int    `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
}

// ThroughputInfo represents throughput statistics
type ThroughputInfo struct {
	MessagesPerMinute float64 `json:"messages_per_minute"`
	MessagesPerHour   float64 `json:"messages_per_hour"`
	BytesPerMinute    float64 `json:"bytes_per_minute"`
	TotalProcessed    int64   `json:"total_processed"`
	TotalBytes        int64   `json:"total_bytes"`
	TimeoutErrors5m   int64   `json:"timeout_errors_5m"`
	ConnCloseErrors5m int64   `json:"conn_close_errors_5m"`
}

// DeliveryStats represents delivery statistics
type DeliveryStats struct {
	TotalDelivered      int64            `json:"total_delivered"`
	TotalFailed         int64            `json:"total_failed"`
	TotalBounced        int64            `json:"total_bounced"`
	TotalDeferred       int64            `json:"total_deferred"`
	SuccessRate         float64          `json:"success_rate"`
	AverageDeliveryTime float64          `json:"average_delivery_time"` // milliseconds
	ByDomain            map[string]int64 `json:"by_domain"`
	ByHour              []HourlyStats    `json:"by_hour"`
	TopSenders          []SenderStats    `json:"top_senders"`
	TopRecipients       []RecipientStats `json:"top_recipients"`
	RecentErrors        []DeliveryError  `json:"recent_errors"`
}

// HourlyStats represents hourly delivery statistics
type HourlyStats struct {
	Hour      string `json:"hour"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// TimeScaleStats represents generic time-scale delivery statistics
type TimeScaleStats struct {
	Label     string `json:"label"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// SenderStats represents sender statistics
type SenderStats struct {
	Sender string `json:"sender"`
	Count  int64  `json:"count"`
}

// RecipientStats represents recipient statistics
type RecipientStats struct {
	Recipient string `json:"recipient"`
	Count     int64  `json:"count"`
}

// DeliveryError represents a delivery error
type DeliveryError struct {
	MessageID string    `json:"message_id"`
	Recipient string    `json:"recipient"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

type ErrorReasonCount struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// Server-level stats tracking
var (
	serverStartTime   = time.Now()
	totalConnections  atomic.Int64
	activeConnections atomic.Int32
	messagesProcessed atomic.Int64
	bytesProcessed    atomic.Int64
)

// TrackMessageProcessed increments the messages processed counter.
// Called by SMTP handlers when a message is successfully received.
func TrackMessageProcessed(size int64) {
	messagesProcessed.Add(1)
	bytesProcessed.Add(size)
}

// TrackConnectionOpened increments connection counters.
func TrackConnectionOpened() {
	totalConnections.Add(1)
	activeConnections.Add(1)
}

// TrackConnectionClosed decrements the active connection counter.
func TrackConnectionClosed() {
	activeConnections.Add(-1)
}

// GetMessagesProcessed returns the total number of messages processed.
func GetMessagesProcessed() int64 {
	return messagesProcessed.Load()
}

// GetBytesProcessed returns the total bytes processed.
func GetBytesProcessed() int64 {
	return bytesProcessed.Load()
}

// handleHealthStats returns server health statistics
func (s *Server) handleHealthStats(w http.ResponseWriter, r *http.Request) {
	// Liveness is public, so load balancers and the container health check
	// can probe without credentials. The details are not: queue depths,
	// throughput, versions and memory tell an outsider a lot, and computing
	// the oldest-message ages walks every queue, which an unauthenticated
	// caller should not be able to trigger in a loop.
	if s.authMiddleware != nil {
		if _, err := s.authMiddleware.authenticate(r); err != nil {
			writeJSON(w, map[string]string{"status": "healthy"})
			return
		}
	}

	ctx := r.Context()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(serverStartTime)
	uptimeFormatted := formatDuration(uptime)

	// Get queue stats
	queueStats := s.queueMgr.GetStats()
	oldestActiveAge := s.getOldestQueueMessageAge(queue.Active)
	oldestDeferredAge := s.getOldestQueueMessageAge(queue.Deferred)
	oldestFailedAge := s.getOldestQueueMessageAge(queue.Failed)

	// Get metrics from Valkey store for throughput calculation
	// Fall back to in-process atomic counters when Valkey is unavailable
	var totalProcessed int64
	var totalBytes int64
	if s.metricsStore != nil {
		metricsData, err := s.metricsStore.GetMetrics(ctx)
		if err == nil && metricsData != nil {
			totalProcessed = metricsData.TotalDelivered + metricsData.TotalFailed + metricsData.TotalDeferred
			totalBytes = GetBytesProcessed()
		}
	}
	// Always include in-process counters as they're more accurate for current session
	if totalProcessed == 0 {
		totalProcessed = GetMessagesProcessed()
		totalBytes = GetBytesProcessed()
	}

	timeoutErrors5m, connCloseErrors5m := s.getRecentConnectionErrorSignals(ctx, 5*time.Minute)

	health := HealthStats{
		Status:          "healthy",
		Uptime:          int64(uptime.Seconds()),
		UptimeFormatted: uptimeFormatted,
		StartedAt:       serverStartTime,
		GoVersion:       runtime.Version(),
		NumGoroutines:   runtime.NumGoroutine(),
		NumCPU:          runtime.NumCPU(),
		Memory: MemoryStats{
			Alloc:        memStats.Alloc,
			TotalAlloc:   memStats.TotalAlloc,
			Sys:          memStats.Sys,
			HeapAlloc:    memStats.HeapAlloc,
			HeapSys:      memStats.HeapSys,
			HeapInuse:    memStats.HeapInuse,
			HeapIdle:     memStats.HeapIdle,
			HeapReleased: memStats.HeapReleased,
			StackInuse:   memStats.StackInuse,
			NumGC:        memStats.NumGC,
			// #nosec G115 -- runtime.MemStats.LastGC is monotonic nanoseconds since epoch; bounded on supported platforms
			LastGC:       int64(memStats.LastGC),
			GCPauseTotal: memStats.PauseTotalNs,
			AllocMB:      float64(memStats.Alloc) / 1024 / 1024,
			SysMB:        float64(memStats.Sys) / 1024 / 1024,
		},
		Queue: QueueHealth{
			TotalMessages:            queueStats.ActiveCount + queueStats.DeferredCount + queueStats.HoldCount + queueStats.FailedCount,
			ActiveCount:              queueStats.ActiveCount,
			DeferredCount:            queueStats.DeferredCount,
			HoldCount:                queueStats.HoldCount,
			FailedCount:              queueStats.FailedCount,
			ProcessorActive:          true,
			OldestActiveAgeSeconds:   int64(oldestActiveAge.Seconds()),
			OldestDeferredAgeSeconds: int64(oldestDeferredAge.Seconds()),
			OldestFailedAgeSeconds:   int64(oldestFailedAge.Seconds()),
			OldestActiveAge:          formatOptionalDuration(oldestActiveAge),
			OldestDeferredAge:        formatOptionalDuration(oldestDeferredAge),
			OldestFailedAge:          formatOptionalDuration(oldestFailedAge),
		},
		SMTP: SMTPHealth{
			Listening:         true,
			ListenAddr:        s.listenAddr,
			TLSEnabled:        false, // Will be set from config
			StartTLSEnabled:   false,
			AuthEnabled:       s.authSystem != nil,
			ActiveConnections: int(activeConnections.Load()),
			TotalConnections:  totalConnections.Load(),
		},
		Throughput: ThroughputInfo{
			MessagesPerMinute: calculateRate(totalProcessed, uptime, time.Minute),
			MessagesPerHour:   calculateRate(totalProcessed, uptime, time.Hour),
			BytesPerMinute:    calculateRate(totalBytes, uptime, time.Minute),
			TotalProcessed:    totalProcessed,
			TotalBytes:        totalBytes,
			TimeoutErrors5m:   timeoutErrors5m,
			ConnCloseErrors5m: connCloseErrors5m,
		},
		ServerVersion:             version.Version,
		ConfiguredAddr:            s.listenAddr,
		AuthEnabled:               s.authSystem != nil,
		FailedQueueRetentionHours: s.getFailedQueueRetentionHours(),
	}

	writeJSON(w, health)
}

// getFailedQueueRetentionHours returns the failed queue retention setting
func (s *Server) getFailedQueueRetentionHours() int {
	if s.queueMgr != nil {
		return s.queueMgr.GetFailedQueueRetentionHours()
	}
	return 0 // Default to immediate deletion
}

func (s *Server) getOldestQueueMessageAge(queueType queue.QueueType) time.Duration {
	if s.queueMgr == nil {
		return 0
	}

	messages, err := s.queueMgr.ListMessages(queueType)
	if err != nil || len(messages) == 0 {
		return 0
	}

	now := time.Now()
	oldest := now
	for _, msg := range messages {
		ts := msg.CreatedAt
		if ts.IsZero() {
			ts = msg.UpdatedAt
		}
		if ts.IsZero() {
			continue
		}
		if ts.Before(oldest) {
			oldest = ts
		}
	}

	if oldest.Equal(now) {
		return 0
	}

	return now.Sub(oldest)
}

func (s *Server) getRecentConnectionErrorSignals(ctx context.Context, window time.Duration) (int64, int64) {
	if s.metricsStore == nil {
		return 0, 0
	}

	recentErrors, err := s.metricsStore.GetRecentErrors(ctx, 250)
	if err != nil || len(recentErrors) == 0 {
		return 0, 0
	}

	cutoff := time.Now().Add(-window)
	var timeoutErrors int64
	var connCloseErrors int64

	for _, e := range recentErrors {
		ts, err := time.Parse(time.RFC3339, e["timestamp"])
		if err != nil || ts.Before(cutoff) {
			continue
		}

		errText := strings.ToLower(e["error"])
		if strings.Contains(errText, "timed out") || strings.Contains(errText, "timeout") {
			timeoutErrors++
		}
		if strings.Contains(errText, "connection unexpectedly closed") || strings.Contains(errText, "connection closed") {
			connCloseErrors++
		}
	}

	return timeoutErrors, connCloseErrors
}

// handleDeliveryStats returns delivery statistics
func (s *Server) handleDeliveryStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get time scale parameter (default: hour)
	timeScale := r.URL.Query().Get("timeScale")
	if timeScale == "" {
		timeScale = "hour"
	}

	// Get queue stats for current queue state
	queueStats := s.queueMgr.GetStats()

	var totalDelivered, totalFailed, totalDeferred int64
	var byHour []HourlyStats
	var data []TimeScaleStats
	var recentErrors []DeliveryError
	var topErrorReasons []ErrorReasonCount

	// Try to get metrics from Valkey store
	if s.metricsStore != nil {
		metricsData, err := s.metricsStore.GetMetrics(ctx)
		if err == nil && metricsData != nil {
			totalDelivered = metricsData.TotalDelivered
			totalFailed = metricsData.TotalFailed
			totalDeferred = metricsData.TotalDeferred
		}

		// Get stats based on time scale
		switch timeScale {
		case "hour":
			hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
			if err == nil {
				byHour = make([]HourlyStats, len(hourlyData))
				data = make([]TimeScaleStats, len(hourlyData))
				for i, h := range hourlyData {
					byHour[i] = HourlyStats(h)
					data[i] = TimeScaleStats{
						Label:     h.Hour,
						Delivered: h.Delivered,
						Failed:    h.Failed,
						Deferred:  h.Deferred,
					}
				}
			}
		case "day":
			data = s.getDailyStats(ctx)
		case "week":
			data = s.getWeeklyStats(ctx)
		case "month":
			data = s.getMonthlyStats(ctx)
		default:
			// Default to hourly for invalid scales
			hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
			if err == nil {
				byHour = make([]HourlyStats, len(hourlyData))
				data = make([]TimeScaleStats, len(hourlyData))
				for i, h := range hourlyData {
					byHour[i] = HourlyStats(h)
					data[i] = TimeScaleStats{
						Label:     h.Hour,
						Delivered: h.Delivered,
						Failed:    h.Failed,
						Deferred:  h.Deferred,
					}
				}
			}
		}

		// Get recent errors from Valkey
		errorsData, err := s.metricsStore.GetRecentErrors(ctx, 10)
		if err == nil {
			for _, e := range errorsData {
				ts, _ := time.Parse(time.RFC3339, e["timestamp"])
				recentErrors = append(recentErrors, DeliveryError{
					MessageID: e["message_id"],
					Recipient: e["recipient"],
					Error:     e["error"],
					Timestamp: ts,
				})
			}
		}
	}

	// If no Valkey data, generate empty hourly stats
	if byHour == nil {
		byHour = make([]HourlyStats, 24)
		now := time.Now()
		for i := 0; i < 24; i++ {
			hour := now.Add(-time.Duration(23-i) * time.Hour)
			byHour[i] = HourlyStats{
				Hour:      hour.Format("15:00"),
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			}
		}
	}

	// Fallback to failed queue for recent errors if Valkey has none
	if len(recentErrors) == 0 {
		failedMsgs, err := s.queueMgr.ListMessages(queue.Failed)
		if err == nil && len(failedMsgs) > 0 {
			limit := 10
			if len(failedMsgs) < limit {
				limit = len(failedMsgs)
			}
			for i := 0; i < limit; i++ {
				msg := failedMsgs[len(failedMsgs)-1-i]
				errorMsg := "Delivery failed"
				if msg.LastError != "" {
					errorMsg = msg.LastError
				}
				recipient := strings.Join(msg.To, ", ")
				recentErrors = append(recentErrors, DeliveryError{
					MessageID: msg.ID,
					Recipient: recipient,
					Error:     errorMsg,
					Timestamp: msg.UpdatedAt,
				})
			}
		}
		// Add current failed queue count to totalFailed
		totalFailed += int64(queueStats.FailedCount)
	}

	topErrorReasons = buildTopErrorReasons(recentErrors, 5)

	// Calculate success rate
	total := totalDelivered + totalFailed
	successRate := 100.0
	if total > 0 {
		successRate = float64(totalDelivered) / float64(total) * 100
	}

	// Build domain stats from current queue
	byDomain := make(map[string]int64)
	allMsgs, err := s.queueMgr.GetAllMessages()
	if err == nil {
		for _, msg := range allMsgs {
			for _, to := range msg.To {
				domain := extractDomain(to)
				byDomain[domain]++
			}
		}
	}

	// Totals for the period the chart shows, so the cards above it agree
	// with it; the all-time counters stay in total_*.
	var window TimeScaleStats
	for _, d := range data {
		window.Delivered += d.Delivered
		window.Failed += d.Failed
		window.Deferred += d.Deferred
	}
	windowRate := 100.0
	if n := window.Delivered + window.Failed; n > 0 {
		windowRate = float64(window.Delivered) / float64(n) * 100
	}

	writeJSON(w, map[string]interface{}{
		"window": map[string]interface{}{
			"delivered":    window.Delivered,
			"failed":       window.Failed,
			"deferred":     window.Deferred,
			"success_rate": windowRate,
		},
		"total_delivered":   totalDelivered,
		"total_failed":      totalFailed,
		"total_deferred":    totalDeferred,
		"success_rate":      successRate,
		"data":              data,
		"by_hour":           byHour, // Keep for backward compatibility
		"recent_errors":     recentErrors,
		"top_error_reasons": topErrorReasons,
	})
}

// extractDomain extracts domain from email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return "unknown"
}

func buildTopErrorReasons(errors []DeliveryError, limit int) []ErrorReasonCount {
	if len(errors) == 0 || limit <= 0 {
		return nil
	}

	reasonCounts := make(map[string]int64)
	for _, e := range errors {
		reason := normalizeErrorReason(e.Error)
		reasonCounts[reason]++
	}

	reasons := make([]ErrorReasonCount, 0, len(reasonCounts))
	for reason, count := range reasonCounts {
		reasons = append(reasons, ErrorReasonCount{Reason: reason, Count: count})
	}

	sort.Slice(reasons, func(i, j int) bool {
		if reasons[i].Count == reasons[j].Count {
			return reasons[i].Reason < reasons[j].Reason
		}
		return reasons[i].Count > reasons[j].Count
	})

	if len(reasons) > limit {
		return reasons[:limit]
	}
	return reasons
}

func normalizeErrorReason(raw string) string {
	text := strings.TrimSpace(strings.ToLower(raw))
	if text == "" {
		return "unknown error"
	}
	switch {
	case strings.Contains(text, "timeout") || strings.Contains(text, "timed out"):
		return "timeout"
	case strings.Contains(text, "connection unexpectedly closed") || strings.Contains(text, "connection closed"):
		return "connection closed"
	case strings.Contains(text, "refused"):
		return "connection refused"
	case strings.Contains(text, "dns") || strings.Contains(text, "no such host"):
		return "dns / host lookup"
	case strings.Contains(text, "tls"):
		return "tls failure"
	default:
		if len(raw) > 80 {
			return raw[:80] + "..."
		}
		return raw
	}
}

// validateTestEmailRequest checks fields that are about to be concatenated into
// RFC 5322 headers. Each address must parse as exactly one address, and the
// subject must not carry CR or LF: a Subject of "x\r\nBcc: ..." is a header
// injection, not a subject. The returned addresses are the bare addr-spec
// forms, stripped of display names.
//
// This outlived the send-test endpoint it was written for. Anything building a
// message from operator- or user-supplied fields needs the same check, and
// deleting it only to write it again later is how the injection comes back.
//
// removed in this change, and the mass mailer that replaces it builds messages
// from the same kind of supplied fields. Deleting security validation along
// with its last caller, then writing it again a change later, is how the
// injection it prevents comes back. Its tests still exercise it.
//
//nolint:unused // Kept deliberately: its only caller was the send-test endpoint
func validateTestEmailRequest(from, to, subject string) (string, string, error) {
	fromAddr, err := mail.ParseAddress(from)
	if err != nil {
		return "", "", fmt.Errorf("from is not a valid address")
	}
	toAddr, err := mail.ParseAddress(to)
	if err != nil {
		return "", "", fmt.Errorf("to is not a valid address")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return "", "", fmt.Errorf("subject must not contain line breaks")
	}
	return fromAddr.Address, toAddr.Address, nil
}

// formatDuration formats a duration as human readable
func formatDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

func formatOptionalDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return formatDuration(d)
}

// getDailyStats aggregates hourly data into daily statistics
// The daily, weekly and monthly charts come from the daily buckets (UTC):
// the last 30 days, the last 12 weeks starting on Mondays, and the last 12
// calendar months, oldest first. A week or month the buckets don't fully
// reach yet just counts what there is.

func (s *Server) dailyBuckets(ctx context.Context, days int) []HourlyStatsData {
	if s.metricsStore == nil {
		return nil
	}
	data, err := s.metricsStore.GetDailyStats(ctx, days)
	if err != nil {
		return nil
	}
	return data
}

func (s *Server) getDailyStats(ctx context.Context) []TimeScaleStats {
	var out []TimeScaleStats
	for _, d := range s.dailyBuckets(ctx, 30) {
		out = append(out, TimeScaleStats{Label: d.Hour, Delivered: d.Delivered, Failed: d.Failed, Deferred: d.Deferred})
	}
	return out
}

func (s *Server) getWeeklyStats(ctx context.Context) []TimeScaleStats {
	return groupDays(s.dailyBuckets(ctx, 7*12+6), func(day time.Time) time.Time {
		return day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7)) // that week's Monday
	}, 12)
}

func (s *Server) getMonthlyStats(ctx context.Context) []TimeScaleStats {
	return groupDays(s.dailyBuckets(ctx, 366), func(day time.Time) time.Time {
		return time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	}, 12)
}

// groupDays sums daily buckets into periods (the period's first day, as
// YYYY-MM-DD) and keeps the last n, oldest first.
func groupDays(days []HourlyStatsData, period func(time.Time) time.Time, n int) []TimeScaleStats {
	var out []TimeScaleStats
	for _, d := range days {
		day, err := time.Parse("2006-01-02", d.Hour)
		if err != nil {
			continue
		}
		label := period(day).Format("2006-01-02")
		if len(out) == 0 || out[len(out)-1].Label != label {
			out = append(out, TimeScaleStats{Label: label})
		}
		last := &out[len(out)-1]
		last.Delivered += d.Delivered
		last.Failed += d.Failed
		last.Deferred += d.Deferred
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// calculateRate calculates a rate per period
func calculateRate(total int64, elapsed time.Duration, period time.Duration) float64 {
	if elapsed == 0 {
		return 0
	}
	return float64(total) / elapsed.Seconds() * period.Seconds()
}
