package antispam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Rspamd represents a Rspamd spam scanner
type Rspamd struct {
	address    string
	timeout    time.Duration
	connected  bool
	scanLimit  int64
	threshold  float64
	config     Config
	httpClient *http.Client
	apiKey     string
}

// RspamdResponse represents the response from Rspamd
type RspamdResponse struct {
	IsSpam    bool                `json:"is_spam"`
	Score     float64             `json:"score"`
	Threshold float64             `json:"threshold"`
	Required  float64             `json:"required_score"`
	Action    string              `json:"action"`
	Symbols   map[string]Symbol   `json:"symbols"`
	MessageID string              `json:"message-id"`
	Milter    map[string]string   `json:"milter"`
	Urls      []string            `json:"urls"`
	Emails    []string            `json:"emails"`
	DKIMSig   []map[string]string `json:"dkim-signature"`
	SPF       map[string]string   `json:"spf"`
	DMARC     map[string]string   `json:"dmarc"`
	Fuzzy     []string            `json:"fuzzy"`
	Time      float64             `json:"time_real"`
	ScanTime  float64             `json:"scan_time"`
}

// Symbol represents a Rspamd rule symbol
type Symbol struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	Description string   `json:"description"`
	Options     []string `json:"options"`
}

// NewRspamd creates a new Rspamd scanner
// defaultRspamdTimeout bounds a scan when the operator has not set one.
//
// This used to default to zero, which as a context deadline expires
// immediately and as an http.Client timeout means "wait forever". Neither
// showed up while the scanner was a local substring check that made no
// requests.
const defaultRspamdTimeout = 30 * time.Second

func NewRspamd(config Config) *Rspamd {
	address := config.Address
	if address == "" {
		address = "http://localhost:11333" // Default Rspamd address
	}
	address = strings.TrimRight(address, "/")

	timeout := durationOption(config.Options, "timeout", defaultRspamdTimeout)

	threshold := config.Threshold
	if threshold == 0 {
		threshold = 6.0 // Default spam threshold
	}

	apiKey := ""
	if key, ok := config.Options["api_key"].(string); ok {
		apiKey = key
	}

	return &Rspamd{
		address:   address,
		timeout:   timeout,
		scanLimit: int64Option(config.Options, "scan_limit", 0),
		threshold: threshold,
		config:    config,
		apiKey:    apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// durationOption reads a timeout from scanner options, accepting either a
// duration or a plain number of seconds, since the config decoder's exact
// numeric type is not guaranteed.
func durationOption(options map[string]interface{}, key string, fallback time.Duration) time.Duration {
	switch v := options[key].(type) {
	case time.Duration:
		if v > 0 {
			return v
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case int64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case string:
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

// int64Option reads a numeric option regardless of how it was typed.
func int64Option(options map[string]interface{}, key string, fallback int64) int64 {
	switch v := options[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return fallback
}

// Connect establishes a connection to the Rspamd server
func (r *Rspamd) Connect() error {
	if r.connected {
		return nil
	}

	// Test connection by pinging the server
	ctx := context.Background()
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", r.address+"/ping", nil)
	if err != nil {
		return fmt.Errorf("failed to create request to Rspamd: %w", err)
	}

	if r.apiKey != "" {
		req.Header.Set("Password", r.apiKey)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Rspamd: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // Ignore error in defer cleanup

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Rspamd returned non-OK status: %d", resp.StatusCode)
	}

	r.connected = true
	return nil
}

// Close closes the connection to the Rspamd server
func (r *Rspamd) Close() error {
	r.connected = false
	return nil
}

// IsConnected returns true if the scanner is connected
func (r *Rspamd) IsConnected() bool {
	return r.connected
}

// Name returns the name of the scanner
func (r *Rspamd) Name() string {
	if r.config.Name != "" {
		return r.config.Name
	}
	return "rspamd"
}

// Type returns the type of the scanner
func (r *Rspamd) Type() string {
	return "rspamd"
}

// ScanBytes scans a byte slice for spam
func (r *Rspamd) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	if r.scanLimit > 0 && int64(len(data)) > r.scanLimit {
		data = data[:r.scanLimit]
	}
	return r.check(ctx, bytes.NewReader(data), int64(len(data)))
}

// ScanReader streams a message to Rspamd without holding it in memory.
func (r *Rspamd) ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	if r.scanLimit > 0 {
		reader = io.LimitReader(reader, r.scanLimit)
	}
	// Length is unknown, so the request is sent chunked.
	return r.check(ctx, reader, -1)
}

// ScanFile streams a file to Rspamd.
//
// This is the path a spooled message takes. It used to return "direct file
// scanning not supported", which meant the caller had to read the message into
// memory first — the thing spooling exists to avoid.
func (r *Rspamd) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	f, err := os.Open(filePath) // #nosec G304 -- caller supplies a queue-owned path
	if err != nil {
		return nil, fmt.Errorf("rspamd: open %s: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()

	length := int64(-1)
	if info, statErr := f.Stat(); statErr == nil {
		length = info.Size()
	}

	if r.scanLimit > 0 && (length < 0 || length > r.scanLimit) {
		return r.check(ctx, io.LimitReader(f, r.scanLimit), -1)
	}
	return r.check(ctx, f, length)
}

// check posts the message to Rspamd's /checkv2 endpoint and interprets the
// verdict.
//
// The body is passed as a reader so the message is streamed to Rspamd rather
// than assembled first. contentLength may be -1 when it is not known, in which
// case the request is chunked.
func (r *Rspamd) check(ctx context.Context, body io.Reader, contentLength int64) (*ScanResult, error) {
	if !r.connected {
		return nil, ErrNotConnected
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.address+"/checkv2", body)
	if err != nil {
		return nil, fmt.Errorf("rspamd: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}
	if r.apiKey != "" {
		req.Header.Set("Password", r.apiKey)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rspamd: request to %s: %w", r.address, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rspamd: unexpected status %s", resp.Status)
	}

	var parsed RspamdResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		// Refusing to guess: a response that cannot be parsed must not become
		// a clean verdict.
		return nil, fmt.Errorf("rspamd: decode response: %w", err)
	}

	return r.resultFrom(parsed), nil
}

// resultFrom turns Rspamd's response into a scan result.
//
// The action is authoritative where present: Rspamd applies its own thresholds
// and policy to reach it, and second-guessing that from the raw score would
// diverge from what the operator configured in Rspamd itself.
func (r *Rspamd) resultFrom(parsed RspamdResponse) *ScanResult {
	threshold := parsed.Required
	if threshold == 0 {
		threshold = parsed.Threshold
	}
	if threshold == 0 {
		threshold = r.threshold
	}

	var clean bool
	switch strings.ToLower(strings.TrimSpace(parsed.Action)) {
	case "reject", "add header", "add_header", "rewrite subject", "rewrite_subject", "soft reject", "soft_reject":
		clean = false
	case "no action", "no_action", "greylist":
		clean = true
	default:
		// No action reported: fall back to comparing the score.
		clean = !(threshold > 0 && parsed.Score >= threshold)
	}

	rules := make([]string, 0, len(parsed.Symbols))
	for name := range parsed.Symbols {
		rules = append(rules, name)
	}
	sort.Strings(rules)

	return &ScanResult{
		Engine:    r.Name(),
		Timestamp: time.Now(),
		Clean:     clean,
		Score:     parsed.Score,
		Threshold: threshold,
		Rules:     rules,
		Details: map[string]interface{}{
			"action":    parsed.Action,
			"scan_time": parsed.ScanTime,
		},
	}
}
