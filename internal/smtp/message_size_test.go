package smtp

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestReconcileMessageSizeLimit_ClampsToMemoryLimit covers the case that used
// to make the server lie: max_size larger than the memory a single session is
// allowed to use.
func TestReconcileMessageSizeLimit_ClampsToMemoryLimit(t *testing.T) {
	cfg := &Config{MaxSize: 50 * 1024 * 1024}
	mem := &MemoryConfig{PerConnectionMemoryLimit: 10 * 1024 * 1024}

	reconcileMessageSizeLimit(cfg, mem, quietLogger())

	if cfg.MaxSize != 10*1024*1024 {
		t.Errorf("max size: got %d, want %d (clamped to per-connection limit)",
			cfg.MaxSize, 10*1024*1024)
	}
}

// TestReconcileMessageSizeLimit_LeavesSmallerSizeAlone makes sure we only ever
// clamp downward — an operator asking for less than the memory ceiling should
// get exactly what they asked for.
func TestReconcileMessageSizeLimit_LeavesSmallerSizeAlone(t *testing.T) {
	cfg := &Config{MaxSize: 5 * 1024 * 1024}
	mem := &MemoryConfig{PerConnectionMemoryLimit: 10 * 1024 * 1024}

	reconcileMessageSizeLimit(cfg, mem, quietLogger())

	if cfg.MaxSize != 5*1024*1024 {
		t.Errorf("max size should be untouched: got %d", cfg.MaxSize)
	}
}

// TestReconcileMessageSizeLimit_IgnoresUnsetMemoryLimit guards against a zero
// or negative limit silently clamping max_size to nothing.
func TestReconcileMessageSizeLimit_IgnoresUnsetMemoryLimit(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		cfg := &Config{MaxSize: 25 * 1024 * 1024}
		reconcileMessageSizeLimit(cfg, &MemoryConfig{PerConnectionMemoryLimit: limit}, quietLogger())
		if cfg.MaxSize != 25*1024*1024 {
			t.Errorf("per-conn limit %d: max size should be untouched, got %d", limit, cfg.MaxSize)
		}
	}
}

// TestMemoryConfigApplyDefaults_PartialConfigDoesNotBrickServer pins the
// footgun that [memory] being TOML-configurable creates: an operator who sets
// only one field must not end up with zeroed thresholds, because a critical
// threshold of 0 rejects every inbound connection.
func TestMemoryConfigApplyDefaults_PartialConfigDoesNotBrickServer(t *testing.T) {
	cfg := &MemoryConfig{PerConnectionMemoryLimit: 4 * 1024 * 1024}
	cfg.ApplyDefaults()

	if cfg.PerConnectionMemoryLimit != 4*1024*1024 {
		t.Errorf("explicitly set field was overwritten: got %d", cfg.PerConnectionMemoryLimit)
	}

	d := DefaultMemoryConfig()
	if cfg.MemoryCriticalThreshold != d.MemoryCriticalThreshold {
		t.Errorf("critical threshold: got %v, want %v", cfg.MemoryCriticalThreshold, d.MemoryCriticalThreshold)
	}
	if cfg.MemoryWarningThreshold != d.MemoryWarningThreshold {
		t.Errorf("warning threshold: got %v, want %v", cfg.MemoryWarningThreshold, d.MemoryWarningThreshold)
	}
	if cfg.GCThreshold != d.GCThreshold {
		t.Errorf("gc threshold: got %v, want %v", cfg.GCThreshold, d.GCThreshold)
	}
	if cfg.MonitoringInterval != d.MonitoringInterval {
		t.Errorf("monitoring interval: got %v, want %v", cfg.MonitoringInterval, d.MonitoringInterval)
	}

	// A bare integer in TOML decodes to nanoseconds; such a value must not
	// survive into the monitor's ticker or it becomes a busy loop.
	busy := &MemoryConfig{MonitoringInterval: 5} // "monitoring_interval = 5"
	busy.ApplyDefaults()
	if busy.MonitoringInterval < time.Second {
		t.Errorf("sub-second monitoring interval survived ApplyDefaults: %v", busy.MonitoringInterval)
	}
	if cfg.MaxMemoryUsage != d.MaxMemoryUsage {
		t.Errorf("max memory usage: got %d, want %d", cfg.MaxMemoryUsage, d.MaxMemoryUsage)
	}
	if cfg.MaxGoroutines != d.MaxGoroutines {
		t.Errorf("max goroutines: got %d, want %d", cfg.MaxGoroutines, d.MaxGoroutines)
	}
}

// TestEHLOAdvertisesEnforcedSize is the end-to-end version: whatever SIZE the
// server puts in its EHLO banner must be a size it will actually accept.
func TestEHLOAdvertisesEnforcedSize(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.MaxSize = 50 * 1024 * 1024 // ask for more than the memory limit allows
	cfg.Resources = &ResourceConfig{
		MaxConnections:    100,
		MaxConcurrent:     50,
		ConnectionTimeout: 30,
	}
	// Deliberately partial: only the field under test is set, which also
	// exercises MemoryConfig.ApplyDefaults filling in the thresholds.
	cfg.Memory = &MemoryConfig{PerConnectionMemoryLimit: 4 * 1024 * 1024}
	cfg.ApplyDefaults()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		if addr := server.Addr(); addr != nil {
			if conn, err = net.Dial("tcp", addr.String()); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become reachable: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if _, err := conn.Write([]byte("EHLO test.example.com\r\n")); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}

	var advertised int64 = -1
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read EHLO response: %v", err)
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "250-SIZE ") {
			advertised, err = strconv.ParseInt(strings.TrimPrefix(trimmed, "250-SIZE "), 10, 64)
			if err != nil {
				t.Fatalf("parse advertised SIZE from %q: %v", trimmed, err)
			}
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	if advertised == -1 {
		t.Fatal("server did not advertise a SIZE capability")
	}
	if advertised != 4*1024*1024 {
		t.Errorf("advertised SIZE %d does not match the enforced per-connection limit %d; "+
			"clients would be told to send more than the server will accept",
			advertised, 4*1024*1024)
	}
}
