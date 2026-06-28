package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MTASTSPolicy represents a fetched MTA-STS policy for a domain (RFC 8461).
// It is discovered via a DNS TXT record at _mta-sts.<domain> and/or
// fetched from https://mta-sts.<domain>/.well-known/mta-sts.txt.
type MTASTSPolicy struct {
	// Version is the policy version (currently "STSv1").
	Version string `json:"version"`

	// Mode is one of "enforce", "testing", or "none".
	Mode string `json:"mode"`

	// MX is the list of MX host patterns allowed by this policy.
	MX []string `json:"mx"`

	// MaxAge is the time (in seconds) that the policy is valid.
	MaxAge int `json:"max_age"`

	// fetchedAt is the time this policy was retrieved (not serialized).
	fetchedAt time.Time

	// expiresAt is when this policy entry becomes stale.
	expiresAt time.Time
}

// IsEnforced returns true if the policy is in enforce mode and not expired.
func (p *MTASTSPolicy) IsEnforced() bool {
	return p.Mode == "enforce" && time.Now().Before(p.expiresAt)
}

// MatchesMX checks whether a given MX hostname matches any of the policy's MX patterns.
func (p *MTASTSPolicy) MatchesMX(mxHost string) bool {
	mxHost = strings.ToLower(strings.TrimSuffix(mxHost, "."))
	for _, pattern := range p.MX {
		pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
		if pattern == mxHost {
			return true
		}
		// Wildcard prefix match: *.example.com matches mail.example.com and example.com
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if mxHost == suffix[1:] || strings.HasSuffix(mxHost, suffix) {
				return true
			}
		}
	}
	return false
}

// MTASTSManager manages MTA-STS policy discovery, caching, and enforcement.
type MTASTSManager struct {
	config     *Config
	logger     *slog.Logger
	cache      map[string]*MTASTSPolicy
	mu         sync.RWMutex
	httpClient *http.Client
	metrics    *MTASTSMetrics
}

// MTASTSMetrics tracks MTA-STS policy fetch/cache statistics.
type MTASTSMetrics struct {
	mu            sync.RWMutex
	PoliciesFetched int64
	CacheHits       int64
	CacheMisses     int64
	FetchErrors     int64
	DNSErrors       int64
	HTTPFetchOK     int64
	CacheSize       int
}

// NewMTASTSManager creates a new MTA-STS policy manager.
func NewMTASTSManager(config *Config) *MTASTSManager {
	return &MTASTSManager{
		config: config,
		logger: slog.Default().With("component", "mtasts-manager"),
		cache:  make(map[string]*MTASTSPolicy),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
			},
		},
		metrics: &MTASTSMetrics{},
	}
}

// GetPolicy retrieves the MTA-STS policy for a domain, using cache when available.
// On cache miss, it attempts to fetch the policy via DNS TXT + HTTPS.
func (m *MTASTSManager) GetPolicy(ctx context.Context, domain string) (*MTASTSPolicy, error) {
	if !m.config.MTASTSEnabled {
		return nil, nil
	}

	domain = strings.ToLower(domain)

	// Check cache first
	m.mu.RLock()
	policy, exists := m.cache[domain]
	m.mu.RUnlock()

	if exists {
		if time.Now().Before(policy.expiresAt) {
			m.metrics.mu.Lock()
			m.metrics.CacheHits++
			m.metrics.mu.Unlock()
			m.logger.Debug("MTA-STS policy cache hit", "domain", domain)
			return policy, nil
		}
		// Expired — remove from cache
		m.mu.Lock()
		delete(m.cache, domain)
		m.mu.Unlock()
	}

	m.metrics.mu.Lock()
	m.metrics.CacheMisses++
	m.metrics.mu.Unlock()

	// Fetch fresh policy
	policy, err := m.fetchPolicy(ctx, domain)
	if err != nil {
		m.metrics.mu.Lock()
		m.metrics.FetchErrors++
		m.metrics.mu.Unlock()
		m.logger.Warn("MTA-STS policy fetch failed", "domain", domain, "error", err)
		return nil, err
	}

	// Cache the policy
	m.mu.Lock()
	m.cache[domain] = policy
	m.metrics.CacheSize = len(m.cache)
	m.mu.Unlock()

	m.metrics.mu.Lock()
	m.metrics.PoliciesFetched++
	m.metrics.mu.Unlock()

	m.logger.Info("MTA-STS policy fetched and cached",
		"domain", domain,
		"mode", policy.Mode,
		"max_age", policy.MaxAge,
		"mx_count", len(policy.MX))

	return policy, nil
}

// fetchPolicy attempts to discover and fetch the MTA-STS policy for a domain.
// It first tries the DNS TXT record, then falls back to HTTPS well-known URL.
func (m *MTASTSManager) fetchPolicy(ctx context.Context, domain string) (*MTASTSPolicy, error) {
	// Strategy 1: Try HTTPS well-known URL directly (most reliable)
	policy, err := m.fetchPolicyFromHTTPS(ctx, domain)
	if err == nil && policy != nil {
		m.metrics.mu.Lock()
		m.metrics.HTTPFetchOK++
		m.metrics.mu.Unlock()
		return policy, nil
	}

	// Strategy 2: Try DNS TXT record at _mta-sts.<domain>
	policy, err = m.fetchPolicyFromDNS(ctx, domain)
	if err == nil && policy != nil {
		return policy, nil
	}

	return nil, fmt.Errorf("no MTA-STS policy found for %s", domain)
}

// fetchPolicyFromHTTPS fetches the MTA-STS policy from the well-known HTTPS URL.
func (m *MTASTSManager) fetchPolicyFromHTTPS(ctx context.Context, domain string) (*MTASTSPolicy, error) {
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "elemta-mtasts/1.0")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	policy := parsePolicyText(string(body))
	if policy == nil {
		return nil, fmt.Errorf("failed to parse policy text")
	}

	now := time.Now()
	policy.fetchedAt = now
	policy.expiresAt = now.Add(time.Duration(policy.MaxAge) * time.Second)

	return policy, nil
}

// fetchPolicyFromDNS attempts to discover MTA-STS via DNS TXT record.
// The TXT record at _mta-sts.<domain> contains policy id and version info.
// This is used as a hint that a policy exists; we still need HTTPS for full policy.
func (m *MTASTSManager) fetchPolicyFromDNS(ctx context.Context, domain string) (*MTASTSPolicy, error) {
	txtName := fmt.Sprintf("_mta-sts.%s", domain)

	// Use the DNS cache's TXT lookup if available, otherwise direct lookup
	records, err := net.DefaultResolver.LookupTXT(ctx, txtName)
	if err != nil {
		m.metrics.mu.Lock()
		m.metrics.DNSErrors++
		m.metrics.mu.Unlock()
		return nil, fmt.Errorf("DNS TXT lookup failed for %s: %w", txtName, err)
	}

	// Check if any record indicates MTA-STS v1
	hasSTSv1 := false
	for _, rec := range records {
		if strings.Contains(rec, "STSv1") {
			hasSTSv1 = true
			break
		}
	}

	if !hasSTSv1 {
		return nil, fmt.Errorf("no STSv1 TXT record found for %s", domain)
	}

	// DNS TXT confirms MTA-STS is supported. Try HTTPS for full policy.
	return m.fetchPolicyFromHTTPS(ctx, domain)
}

// parsePolicyText parses MTA-STS policy text format into an MTASTSPolicy struct.
// Reference: RFC 8461 Section 3.1
func parsePolicyText(text string) *MTASTSPolicy {
	policy := &MTASTSPolicy{
		Version: "",
		Mode:    "none",
		MaxAge:  86400, // default 1 day
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "version":
			policy.Version = value
		case "mode":
			policy.Mode = strings.ToLower(value)
		case "max_age":
			var age int
			if _, err := fmt.Sscanf(value, "%d", &age); err == nil && age > 0 {
				policy.MaxAge = age
			}
		case "mx":
			policy.MX = append(policy.MX, value)
		}
	}

	// Validate: must be STSv1 with a valid mode
	if policy.Version != "STSv1" {
		return nil
	}
	if policy.Mode != "enforce" && policy.Mode != "testing" && policy.Mode != "none" {
		return nil
	}

	return policy
}

// EnforcePolicy checks whether delivery to a given MX host complies with the domain's MTA-STS policy.
// Returns nil if delivery is allowed, or an error describing the policy violation.
func (m *MTASTSManager) EnforcePolicy(ctx context.Context, domain, mxHost string, tlsUsed bool) error {
	if !m.config.MTASTSEnabled {
		return nil
	}

	policy, err := m.GetPolicy(ctx, domain)
	if err != nil {
		// If we can't fetch the policy, log and allow delivery (soft fail)
		m.logger.Warn("MTA-STS policy fetch failed, allowing delivery",
			"domain", domain,
			"mx_host", mxHost,
			"error", err)
		return nil
	}

	if policy == nil {
		return nil
	}

	// In "none" mode, no enforcement
	if policy.Mode == "none" {
		return nil
	}

	// Check if MX host matches policy
	if !policy.MatchesMX(mxHost) {
		if policy.IsEnforced() {
			return &DeliveryError{
				Type:      ErrorTypePolicy,
				Message:   fmt.Sprintf("MTA-STS: MX host %s does not match policy for %s", mxHost, domain),
				Details:   fmt.Sprintf("policy MX patterns: %v", policy.MX),
				Temporary: false,
				Retryable: false,
				Timestamp: time.Now(),
			}
		}
		m.logger.Warn("MTA-STS: MX host not in policy (testing mode, allowing)",
			"domain", domain,
			"mx_host", mxHost,
			"policy_mx", policy.MX)
		return nil
	}

	// MX matches — enforce TLS requirement
	if policy.IsEnforced() && !tlsUsed {
		return &DeliveryError{
			Type:      ErrorTypePolicy,
			Message:   fmt.Sprintf("MTA-STS: TLS required for %s but not used", domain),
			Details:   fmt.Sprintf("policy mode: %s", policy.Mode),
			Temporary: true,
			Retryable: true,
			Timestamp: time.Now(),
		}
	}

	m.logger.Debug("MTA-STS policy check passed",
		"domain", domain,
		"mx_host", mxHost,
		"tls_used", tlsUsed,
		"policy_mode", policy.Mode)

	return nil
}

// ClearCache removes all cached policies.
func (m *MTASTSManager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]*MTASTSPolicy)
	m.metrics.mu.Lock()
	m.metrics.CacheSize = 0
	m.metrics.mu.Unlock()
	m.logger.Info("MTA-STS policy cache cleared")
}

// GetStats returns current MTA-STS manager statistics.
func (m *MTASTSManager) GetStats() map[string]interface{} {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()
	return map[string]interface{}{
		"policies_fetched": m.metrics.PoliciesFetched,
		"cache_hits":       m.metrics.CacheHits,
		"cache_misses":     m.metrics.CacheMisses,
		"fetch_errors":     m.metrics.FetchErrors,
		"dns_errors":       m.metrics.DNSErrors,
		"http_fetch_ok":    m.metrics.HTTPFetchOK,
		"cache_size":       m.metrics.CacheSize,
	}
}

// cleanup runs periodic cleanup of expired policy entries.
func (m *MTASTSManager) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.performCleanup()
		}
	}
}

// performCleanup removes expired entries from the policy cache.
func (m *MTASTSManager) performCleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expired := 0
	for domain, policy := range m.cache {
		if now.After(policy.expiresAt) {
			delete(m.cache, domain)
			expired++
		}
	}

	if expired > 0 {
		m.metrics.mu.Lock()
		m.metrics.CacheSize = len(m.cache)
		m.metrics.mu.Unlock()
		m.logger.Debug("MTA-STS policy cache cleanup", "expired", expired)
	}
}

// MarshalJSON for MTASTSPolicy (excludes internal fields).
func (p *MTASTSPolicy) MarshalJSON() ([]byte, error) {
	type Alias MTASTSPolicy
	return json.Marshal(&struct {
		*Alias
		FetchedAt time.Time `json:"fetched_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}{
		Alias:     (*Alias)(p),
		FetchedAt: p.fetchedAt,
		ExpiresAt: p.expiresAt,
	})
}
