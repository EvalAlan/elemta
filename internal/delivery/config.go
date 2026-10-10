package delivery

// Config holds the MTA-STS settings. The rest of the original delivery manager
// was never wired in; outbound delivery lives in internal/queue.
type Config struct {
	MTASTSEnabled   bool `yaml:"mtasts_enabled" json:"mtasts_enabled"`
	MTASTSCacheSize int  `yaml:"mtasts_cache_size" json:"mtasts_cache_size"`
}

// DefaultConfig returns MTA-STS enforcement on with a 1000-policy cache.
func DefaultConfig() *Config {
	return &Config{
		MTASTSEnabled:   true,
		MTASTSCacheSize: 1000,
	}
}
