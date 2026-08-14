package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// The setting has to survive the whole round trip: readable on GET, accepted on
// PUT, and reflected back. A control that renders but does not persist is the
// failure this repository has produced more than once.
func TestQueueTombstoneBodySettingRoundTrips(t *testing.T) {
	// A real MainConfig, because /api/config answers 503 without one and this
	// test is about what that endpoint reports.
	dir := t.TempDir()
	// persistConfig edits the file in place, so there has to be one.
	configPath := filepath.Join(dir, "elemta.toml")
	if err := os.WriteFile(configPath, []byte("hostname = \"test.example.com\"\n\n[queue]\nbackend = \"file\"\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	server, err := NewServer(&Config{
		Enabled:     true,
		ListenAddr:  "127.0.0.1:0",
		WebRoot:     dir,
		AuthEnabled: false,
	}, &MainConfig{
		Hostname:     "test.example.com",
		QueueDir:     dir,
		QueueBackend: "file",
	}, dir, 0, configPath)
	if err != nil {
		t.Fatalf("building server: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("starting server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Stop()
		server.queueMgr.Stop()
	})
	baseURL := "http://" + server.listener.Addr().String() + "/api"
	client := &http.Client{}

	get := func() map[string]interface{} {
		t.Helper()
		resp, err := client.Get(baseURL + "/config")
		if err != nil {
			t.Fatalf("GET /config: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /config returned %d", resp.StatusCode)
		}
		var out map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decoding config: %v", err)
		}
		return out
	}

	// Absent from the config file means the safe default, not false.
	cfg := get()
	if got, ok := cfg["queue_retain_tombstone_body"]; !ok || got != true {
		t.Fatalf("queue_retain_tombstone_body = %v (present=%v), want true by default — "+
			"the default must be the side that cannot refuse mail after a rollback", got, ok)
	}
	// The backend is shown so an operator knows what they are looking at.
	if _, ok := cfg["queue_backend"]; !ok {
		t.Error("queue_backend is not reported; the UI shows it read-only")
	}

	// Turn it off.
	body, _ := json.Marshal(map[string]interface{}{"queue_retain_tombstone_body": false})
	req, err := http.NewRequest(http.MethodPut, baseURL+"/config", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT /config: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /config returned %d", resp.StatusCode)
	}

	if got := get()["queue_retain_tombstone_body"]; got != false {
		t.Errorf("after turning it off, GET reports %v; the setting did not stick", got)
	}
}
