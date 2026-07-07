package delivery

import (
	"context"
	"testing"
	"time"
)

func TestParsePolicyText(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expectNil  bool
		expectMode string
		expectMX   []string
		expectAge  int
	}{
		{
			name: "valid enforce policy",
			input: `version: STSv1
mode: enforce
max_age: 604800
mx: mail.example.com
mx: mx.example.com
`,
			expectNil:  false,
			expectMode: "enforce",
			expectMX:   []string{"mail.example.com", "mx.example.com"},
			expectAge:  604800,
		},
		{
			name: "valid testing policy",
			input: `version: STSv1
mode: testing
max_age: 86400
mx: *.example.com
`,
			expectNil:  false,
			expectMode: "testing",
			expectMX:   []string{"*.example.com"},
			expectAge:  86400,
		},
		{
			name: "none mode",
			input: `version: STSv1
mode: none
max_age: 3600
`,
			expectNil:  false,
			expectMode: "none",
			expectAge:  3600,
		},
		{
			name:      "invalid version",
			input:     `version: STSv2\nmode: enforce\n`,
			expectNil: true,
		},
		{
			name:      "invalid mode",
			input:     `version: STSv1\nmode: strict\n`,
			expectNil: true,
		},
		{
			name:      "empty input",
			input:     "",
			expectNil: true,
		},
		{
			name: "comments and blank lines",
			input: `# This is a comment
version: STSv1

mode: enforce
# Another comment
mx: mail.example.com
`,
			expectNil:  false,
			expectMode: "enforce",
			expectMX:   []string{"mail.example.com"},
			expectAge:  86400, // default
		},
		{
			name: "malformed max_age uses default",
			input: `version: STSv1
mode: enforce
max_age: not_a_number
mx: mail.example.com
`,
			expectNil:  false,
			expectMode: "enforce",
			expectMX:   []string{"mail.example.com"},
			expectAge:  86400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := parsePolicyText(tt.input)
			if tt.expectNil {
				if policy != nil {
					t.Errorf("expected nil policy, got %+v", policy)
				}
				return
			}
			if policy == nil {
				t.Fatalf("expected non-nil policy, got nil")
			}
			if policy.Mode != tt.expectMode {
				t.Errorf("expected mode %q, got %q", tt.expectMode, policy.Mode)
			}
			if len(policy.MX) != len(tt.expectMX) {
				t.Errorf("expected %d MX records, got %d", len(tt.expectMX), len(policy.MX))
			}
			for i, mx := range tt.expectMX {
				if i < len(policy.MX) && policy.MX[i] != mx {
					t.Errorf("expected MX[%d]=%q, got %q", i, mx, policy.MX[i])
				}
			}
			if policy.MaxAge != tt.expectAge {
				t.Errorf("expected max_age %d, got %d", tt.expectAge, policy.MaxAge)
			}
		})
	}
}

func TestMTASTSPolicyMatchesMX(t *testing.T) {
	tests := []struct {
		name     string
		policy   *MTASTSPolicy
		mxHost   string
		expected bool
	}{
		{
			name: "exact match",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"mail.example.com"},
			},
			mxHost:   "mail.example.com",
			expected: true,
		},
		{
			name: "wildcard match",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"*.example.com"},
			},
			mxHost:   "mail.example.com",
			expected: true,
		},
		{
			name: "wildcard matches base domain",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"*.example.com"},
			},
			mxHost:   "example.com",
			expected: true,
		},
		{
			name: "no match",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"mail.example.com"},
			},
			mxHost:   "mail.other.com",
			expected: false,
		},
		{
			name: "case insensitive",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"Mail.Example.COM"},
			},
			mxHost:   "mail.example.com",
			expected: true,
		},
		{
			name: "trailing dot stripped",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"mail.example.com"},
			},
			mxHost:   "mail.example.com.",
			expected: true,
		},
		{
			name: "multiple patterns - second matches",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{"mx1.example.com", "mx2.example.com"},
			},
			mxHost:   "mx2.example.com",
			expected: true,
		},
		{
			name: "empty MX list",
			policy: &MTASTSPolicy{
				Mode: "enforce",
				MX:   []string{},
			},
			mxHost:   "anything.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.MatchesMX(tt.mxHost)
			if result != tt.expected {
				t.Errorf("MatchesMX(%q) = %v, want %v", tt.mxHost, result, tt.expected)
			}
		})
	}
}

func TestMTASTSPolicyIsEnforced(t *testing.T) {
	tests := []struct {
		name     string
		policy   *MTASTSPolicy
		expected bool
	}{
		{
			name: "enforce mode, not expired",
			policy: &MTASTSPolicy{
				Mode:      "enforce",
				expiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "enforce mode, expired",
			policy: &MTASTSPolicy{
				Mode:      "enforce",
				expiresAt: time.Now().Add(-1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "testing mode, not expired",
			policy: &MTASTSPolicy{
				Mode:      "testing",
				expiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "none mode",
			policy: &MTASTSPolicy{
				Mode:      "none",
				expiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.IsEnforced()
			if result != tt.expected {
				t.Errorf("IsEnforced() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMTASTSManagerCache(t *testing.T) {
	config := DefaultConfig()
	config.MTASTSEnabled = true
	mgr := NewMTASTSManager(config)

	t.Run("CacheMiss", func(t *testing.T) {
		// Cache should be empty
		mgr.mu.RLock()
		_, exists := mgr.cache["example.com"]
		mgr.mu.RUnlock()
		if exists {
			t.Error("Expected cache to be empty for example.com")
		}
	})

	t.Run("CacheStore", func(t *testing.T) {
		policy := &MTASTSPolicy{
			Version:   "STSv1",
			Mode:      "enforce",
			MaxAge:    3600,
			MX:        []string{"mail.example.com"},
			fetchedAt: time.Now(),
			expiresAt: time.Now().Add(1 * time.Hour),
		}
		mgr.mu.Lock()
		mgr.cache["example.com"] = policy
		mgr.mu.Unlock()

		// Verify it's cached
		mgr.mu.RLock()
		cached, exists := mgr.cache["example.com"]
		mgr.mu.RUnlock()
		if !exists {
			t.Error("Expected policy to be cached")
		}
		if cached.Mode != "enforce" {
			t.Errorf("Expected mode enforce, got %s", cached.Mode)
		}
	})

	t.Run("CacheExpiration", func(t *testing.T) {
		// Add an expired entry
		mgr.mu.Lock()
		mgr.cache["expired.example.com"] = &MTASTSPolicy{
			Version:   "STSv1",
			Mode:      "enforce",
			MaxAge:    3600,
			fetchedAt: time.Now().Add(-2 * time.Hour),
			expiresAt: time.Now().Add(-1 * time.Hour), // expired
		}
		mgr.mu.Unlock()

		// performCleanup should remove it
		mgr.performCleanup()

		mgr.mu.RLock()
		_, exists := mgr.cache["expired.example.com"]
		mgr.mu.RUnlock()
		if exists {
			t.Error("Expected expired entry to be cleaned up")
		}
	})

	t.Run("ClearCache", func(t *testing.T) {
		mgr.mu.Lock()
		mgr.cache["test.com"] = &MTASTSPolicy{Mode: "enforce"}
		mgr.mu.Unlock()

		mgr.ClearCache()

		mgr.mu.RLock()
		count := len(mgr.cache)
		mgr.mu.RUnlock()
		if count != 0 {
			t.Errorf("Expected empty cache after ClearCache, got %d entries", count)
		}
	})
}

func TestMTASTSManagerDisabled(t *testing.T) {
	config := DefaultConfig()
	config.MTASTSEnabled = false
	mgr := NewMTASTSManager(config)

	t.Run("GetPolicyReturnsNil", func(t *testing.T) {
		ctx := context.Background()
		policy, err := mgr.GetPolicy(ctx, "example.com")
		if err != nil {
			t.Errorf("Expected nil error when disabled, got: %v", err)
		}
		if policy != nil {
			t.Errorf("Expected nil policy when disabled, got: %+v", policy)
		}
	})

	t.Run("EnforcePolicyNoOp", func(t *testing.T) {
		ctx := context.Background()
		err := mgr.EnforcePolicy(ctx, "example.com", "mail.example.com", false)
		if err != nil {
			t.Errorf("Expected nil error when disabled, got: %v", err)
		}
	})
}

func TestMTASTSManagerMetrics(t *testing.T) {
	config := DefaultConfig()
	config.MTASTSEnabled = true
	mgr := NewMTASTSManager(config)

	stats := mgr.GetStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	keys := []string{"policies_fetched", "cache_hits", "cache_misses", "fetch_errors", "dns_errors", "http_fetch_ok", "cache_size"}
	for _, key := range keys {
		if _, ok := stats[key]; !ok {
			t.Errorf("Expected stats to contain key %q", key)
		}
	}
}

func TestMTASTSManagerGetStats(t *testing.T) {
	config := DefaultConfig()
	config.MTASTSEnabled = true
	mgr := NewMTASTSManager(config)

	// Add some cache entries directly
	mgr.mu.Lock()
	mgr.cache["a.com"] = &MTASTSPolicy{Mode: "enforce", expiresAt: time.Now().Add(time.Hour)}
	mgr.cache["b.com"] = &MTASTSPolicy{Mode: "testing", expiresAt: time.Now().Add(time.Hour)}
	mgr.mu.Unlock()

	// Verify internal cache has 2 entries
	mgr.mu.RLock()
	cacheLen := len(mgr.cache)
	mgr.mu.RUnlock()
	if cacheLen != 2 {
		t.Errorf("Expected 2 cached policies, got %d", cacheLen)
	}

	// Verify stats returns non-nil with expected keys
	stats := mgr.GetStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}
	if _, ok := stats["cache_size"]; !ok {
		t.Error("Expected stats to contain cache_size key")
	}
}
