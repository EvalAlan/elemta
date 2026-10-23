package metrics

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

// DeliveryMetrics holds delivery statistics
type DeliveryMetrics struct {
	TotalDelivered int64     `json:"total_delivered"`
	TotalFailed    int64     `json:"total_failed"`
	TotalDeferred  int64     `json:"total_deferred"`
	TotalReceived  int64     `json:"total_received"`
	LastUpdated    time.Time `json:"last_updated"`
}

// HourlyStats holds hourly delivery counts
type HourlyStats struct {
	Hour      string `json:"hour"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// ValkeyStore provides metrics storage using Valkey
type ValkeyStore struct {
	client valkey.Client
	prefix string
}

// NewValkeyStore creates a new Valkey-backed metrics store
func NewValkeyStore(addr string) (*ValkeyStore, error) {
	client, err := valkeyaddr.NewClient(addr, nil)
	if err != nil {
		return nil, err
	}

	return &ValkeyStore{
		client: client,
		prefix: "elemta:metrics:",
	}, nil
}

// Close closes the Valkey connection
func (s *ValkeyStore) Close() {
	s.client.Close()
}

// Buckets for the Reports chart, in UTC. An hourly bucket must outlive the
// 24-hour window it is shown in, or the oldest hour reads as empty, so it
// is kept two days. Daily buckets back the daily, weekly and monthly views
// and are kept a little over a year, for the twelve-month chart.
const (
	hourlyRetention = 48 * time.Hour
	dailyRetention  = 400 * 24 * time.Hour
)

// incrCounter increments a running total and its hourly and daily buckets.
func (s *ValkeyStore) incrCounter(ctx context.Context, counterName string) error {
	now := time.Now().UTC()
	key := s.prefix + counterName
	hourKey := s.prefix + "hourly:" + now.Format("2006-01-02:15") + ":" + counterName
	dayKey := s.prefix + "daily:" + now.Format("2006-01-02") + ":" + counterName

	cmds := []valkey.Completed{
		s.client.B().Incr().Key(key).Build(),
		s.client.B().Incr().Key(hourKey).Build(),
		s.client.B().Expire().Key(hourKey).Seconds(int64(hourlyRetention.Seconds())).Build(),
		s.client.B().Incr().Key(dayKey).Build(),
		s.client.B().Expire().Key(dayKey).Seconds(int64(dailyRetention.Seconds())).Build(),
		s.client.B().Set().Key(s.prefix + "last_updated").Value(now.Format(time.RFC3339)).Build(),
	}

	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// IncrDelivered increments the delivered counter
func (s *ValkeyStore) IncrDelivered(ctx context.Context) error {
	return s.incrCounter(ctx, "delivered")
}

// IncrFailed increments the failed counter
func (s *ValkeyStore) IncrFailed(ctx context.Context) error {
	return s.incrCounter(ctx, "failed")
}

// IncrDeferred increments the deferred counter
func (s *ValkeyStore) IncrDeferred(ctx context.Context) error {
	return s.incrCounter(ctx, "deferred")
}

// IncrReceived increments the received counter
func (s *ValkeyStore) IncrReceived(ctx context.Context) error {
	key := s.prefix + "received"

	cmds := []valkey.Completed{
		s.client.B().Incr().Key(key).Build(),
		s.client.B().Set().Key(s.prefix + "last_updated").Value(time.Now().Format(time.RFC3339)).Build(),
	}

	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// GetMetrics retrieves current delivery metrics
func (s *ValkeyStore) GetMetrics(ctx context.Context) (*DeliveryMetrics, error) {
	metrics := &DeliveryMetrics{}

	// Get counters
	delivered, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"delivered").Build()).ToString()
	failed, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"failed").Build()).ToString()
	deferred, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"deferred").Build()).ToString()
	received, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"received").Build()).ToString()
	lastUpdated, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"last_updated").Build()).ToString()

	metrics.TotalDelivered, _ = strconv.ParseInt(delivered, 10, 64)
	metrics.TotalFailed, _ = strconv.ParseInt(failed, 10, 64)
	metrics.TotalDeferred, _ = strconv.ParseInt(deferred, 10, 64)
	metrics.TotalReceived, _ = strconv.ParseInt(received, 10, 64)
	metrics.LastUpdated, _ = time.Parse(time.RFC3339, lastUpdated)

	return metrics, nil
}

// GetHourlyStats retrieves hourly statistics for the last 24 hours. Each
// bucket is labelled with the RFC 3339 time its hour starts (UTC), so the
// dashboard can show it in the viewer's own time zone.
func (s *ValkeyStore) GetHourlyStats(ctx context.Context) ([]HourlyStats, error) {
	stats := make([]HourlyStats, 24)
	now := time.Now().UTC().Truncate(time.Hour)

	for i := 0; i < 24; i++ {
		hour := now.Add(-time.Duration(23-i) * time.Hour)
		hourStr := hour.Format("2006-01-02:15")
		displayHour := hour.Format(time.RFC3339)

		delivered, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"hourly:"+hourStr+":delivered").Build()).ToString()
		failed, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"hourly:"+hourStr+":failed").Build()).ToString()
		deferred, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"hourly:"+hourStr+":deferred").Build()).ToString()

		stats[i] = HourlyStats{
			Hour: displayHour,
		}
		stats[i].Delivered, _ = strconv.ParseInt(delivered, 10, 64)
		stats[i].Failed, _ = strconv.ParseInt(failed, 10, 64)
		stats[i].Deferred, _ = strconv.ParseInt(deferred, 10, 64)
	}

	return stats, nil
}

// AddRecentError stores a recent delivery error
func (s *ValkeyStore) AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error {
	errorData := map[string]string{
		"message_id": messageID,
		"recipient":  recipient,
		"error":      errorMsg,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(errorData)
	if err != nil {
		return err
	}

	key := s.prefix + "recent_errors"
	cmds := []valkey.Completed{
		s.client.B().Lpush().Key(key).Element(string(data)).Build(),
		s.client.B().Ltrim().Key(key).Start(0).Stop(99).Build(), // Keep last 100 errors
	}

	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// GetRecentErrors retrieves recent delivery errors
func (s *ValkeyStore) GetRecentErrors(ctx context.Context, limit int64) ([]map[string]string, error) {
	key := s.prefix + "recent_errors"
	result, err := s.client.Do(ctx, s.client.B().Lrange().Key(key).Start(0).Stop(limit-1).Build()).AsStrSlice()
	if err != nil {
		return nil, err
	}

	errors := make([]map[string]string, 0, len(result))
	for _, item := range result {
		var errorData map[string]string
		if err := json.Unmarshal([]byte(item), &errorData); err != nil {
			continue
		}
		errors = append(errors, errorData)
	}

	return errors, nil
}

// GetDailyStats returns the last days days (UTC), oldest first, each
// labelled YYYY-MM-DD. One MGET reads them all.
func (s *ValkeyStore) GetDailyStats(ctx context.Context, days int) ([]HourlyStats, error) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	stats := make([]HourlyStats, days)
	keys := make([]string, 0, 3*days)
	for i := 0; i < days; i++ {
		day := today.AddDate(0, 0, -(days - 1 - i)).Format("2006-01-02")
		stats[i].Hour = day
		for _, c := range []string{"delivered", "failed", "deferred"} {
			keys = append(keys, s.prefix+"daily:"+day+":"+c)
		}
	}
	values, err := s.client.Do(ctx, s.client.B().Mget().Key(keys...).Build()).ToArray()
	if err != nil {
		return nil, err
	}
	for i, v := range values {
		n, _ := v.AsInt64()
		switch i % 3 {
		case 0:
			stats[i/3].Delivered = n
		case 1:
			stats[i/3].Failed = n
		case 2:
			stats[i/3].Deferred = n
		}
	}
	return stats, nil
}
