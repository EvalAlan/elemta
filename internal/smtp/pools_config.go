package smtp

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/EvalAlan/elemta/internal/queue"
)

// valkeyAddress is the Valkey that sender telemetry writes to. Shared
// delivery state uses the same one so a deployment has one Valkey to run and
// one setting to point at it.
func valkeyAddress() string {
	if addr := os.Getenv("VALKEY_ADDR"); addr != "" {
		return addr
	}
	return "elemta-valkey:6379"
}

func sharedStatePrefix(d *DeliveryConfig) string {
	if d == nil || d.SharedStatePrefix == "" {
		return queue.DefaultSharedStatePrefix
	}
	return d.SharedStatePrefix
}

// poolsSettings resolves the pool configuration, defaulting the state file
// into the queue directory.
func poolsSettings(config *Config) queue.PoolsConfig {
	if config.Delivery == nil {
		return queue.PoolsConfig{}
	}
	stateFile := config.Delivery.PoolStateFile
	if stateFile == "" {
		stateFile = filepath.Join(config.QueueDir, "pool-state.json")
	}
	return queue.PoolsConfig{
		Pools:       config.Delivery.Pools,
		DefaultPool: config.Delivery.DefaultPool,
		StateFile:   stateFile,
	}
}

// poolsFingerprint identifies a pool configuration, so a reload rebuilds the
// router only when pools actually changed. The config file is reloaded on
// every save, and rebuilding for an unrelated edit would re-run the bind
// check and churn the state file for nothing.
func poolsFingerprint(pc queue.PoolsConfig) string {
	if len(pc.Pools) == 0 && pc.DefaultPool == "" {
		return ""
	}
	b, err := json.Marshal(pc)
	if err != nil {
		// Unreachable for plain data; an empty fingerprint would make every
		// reload look like "pools removed", so fail towards "changed".
		return "unmarshalable"
	}
	return string(b)
}

// buildReloadPools builds the pool router a reload should install. changed is
// false when pools are as they were, or when this node sends nothing over
// remote SMTP (pools are ignored there at startup too). A nil router with
// changed true means pools were removed.
func (s *Server) buildReloadPools(config *Config) (router *queue.PoolRouter, fingerprint string, changed bool, err error) {
	if s.queueProcessor == nil || !s.queueProcessor.SendsFromPools() {
		return nil, "", false, nil
	}
	pc := poolsSettings(config)
	fingerprint = poolsFingerprint(pc)
	if fingerprint == s.poolsFingerprint {
		return nil, fingerprint, false, nil
	}
	if fingerprint == "" {
		return nil, "", true, nil
	}
	router, err = queue.NewPoolRouter(pc, s.slogger)
	if err != nil {
		return nil, "", false, err
	}
	if err := router.CheckLocalAddresses(); err != nil {
		return nil, "", false, err
	}
	return router, fingerprint, true, nil
}
