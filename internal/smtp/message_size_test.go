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

// max_size used to be clamped down to the per-connection memory limit, because
// DATA was accumulated on the heap and a session could not exceed it. Message
// data is spooled to disk now, for both DATA and BDAT, so the limit is
// max_size and disk rather than memory.

// TestLargeMaxSizeIsNotClampedByMemory pins that a max_size far above the
// per-connection memory limit survives startup untouched.
func TestLargeMaxSizeIsNotClampedByMemory(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.MaxSize = 200 * 1024 * 1024 // far above any per-connection memory limit
	cfg.Memory = &MemoryConfig{PerConnectionMemoryLimit: 4 * 1024 * 1024}
	cfg.ApplyDefaults()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if cfg.MaxSize != 200*1024*1024 {
		t.Errorf("max_size was altered at startup: got %d, want %d", cfg.MaxSize, 200*1024*1024)
	}
}

// TestEHLOAdvertisesConfiguredSize is the end-to-end form: whatever SIZE the
// server advertises must be what was configured, since it can now accept it.
func TestEHLOAdvertisesConfiguredSize(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.MaxSize = 100 * 1024 * 1024
	cfg.Memory = &MemoryConfig{PerConnectionMemoryLimit: 4 * 1024 * 1024}
	cfg.ApplyDefaults()

	conn, reader := dialGreetedWithBanner(t, cfg)
	defer conn.Close()

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
				t.Fatalf("parse advertised SIZE: %v", err)
			}
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	if advertised != 100*1024*1024 {
		t.Errorf("advertised SIZE %d, want the configured %d", advertised, 100*1024*1024)
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

// dialGreetedWithBanner starts a server, connects, sends EHLO and returns the
// connection positioned to read the EHLO response.
func dialGreetedWithBanner(t *testing.T, cfg *Config) (net.Conn, *bufio.Reader) {
	t.Helper()

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
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if _, err := conn.Write([]byte("EHLO test.example.com\r\n")); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	return conn, reader
}
