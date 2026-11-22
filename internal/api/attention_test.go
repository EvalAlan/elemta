package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/queue"
	"github.com/stretchr/testify/require"
)

func TestLimitHysteresis(t *testing.T) {
	for _, c := range []struct {
		v      float64
		before int
		want   int
	}{
		{84.9, 0, 0}, {85, 0, 1}, {94.9, 0, 1}, {95, 0, 2}, {95, 1, 2},
		{82, 1, 1}, {81.9, 1, 0}, {92, 2, 2}, {91.9, 2, 1}, {82, 2, 1}, {81.9, 2, 0},
	} {
		require.Equal(t, c.want, diskLimit.level(c.v, c.before), "%v after level %d", c.v, c.before)
	}
}

func TestResourceAlerts(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	space, inodes := 50.0, 5.0
	var diskErr error
	var active []queue.Message
	deferred := 0
	m := &resourceMonitor{diskPaths: []string{"/queue", "/config"}, levels: map[string]int{},
		disk: func(p string) (diskUsage, error) {
			return diskUsage{Path: p, Device: "1", SpacePercent: space, InodePercent: inodes, FreeBytes: 5 << 30}, diskErr
		},
		list: func(q queue.QueueType) ([]queue.Message, error) {
			if q == queue.Active {
				return active, nil
			}
			return make([]queue.Message, deferred), nil
		}}
	alerts := map[string]*alerter{}
	step := func(after time.Duration, want ...string) {
		t.Helper()
		now = now.Add(after)
		got := []string{}
		for _, n := range m.check(alerts, "mail.example.com", now) {
			got = append(got, n.subject)
		}
		if want == nil {
			want = []string{}
		}
		require.Equal(t, want, got)
	}
	const five = resourceWatchEvery

	step(0)
	space = 86
	// Two paths on one filesystem are one alert.
	step(five, "Disk space warning on mail.example.com")
	space = 84
	step(five) // on the line: neither recovered nor new
	space = 86
	step(five)
	space = 96
	step(five, "Disk space critical on mail.example.com")
	space = 90
	step(five) // better, still bad
	space = 95
	step(five, "Disk space critical on mail.example.com")
	step(25*time.Hour, "Disk space critical on mail.example.com")
	diskErr = errors.New("gone")
	step(five) // unreadable isn't recovered
	require.Equal(t, attentionUnknown, m.attention(now)[0].Severity)
	diskErr = nil
	step(five)
	space = 40
	step(five, "Disk space: back to normal on mail.example.com")
	step(five)

	inodes = 85
	step(five, "Disk file slots warning on mail.example.com")
	inodes = 5
	step(five, "Disk file slots: back to normal on mail.example.com")

	// A retry of an old deferral has only just arrived.
	active = []queue.Message{{CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(five - time.Minute)}}
	step(five)
	active = []queue.Message{{CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(five - 16*time.Minute)}}
	step(five, "Queue not moving warning on mail.example.com")
	active[0].UpdatedAt = now.Add(five - 61*time.Minute)
	step(five, "Queue not moving critical on mail.example.com")
	active = nil
	step(five, "Queue not moving: back to normal on mail.example.com")

	deferred = 100
	step(five, "Deferred mail warning on mail.example.com")
	deferred = 85
	step(five)
	deferred = 1000
	step(five, "Deferred mail critical on mail.example.com")
	deferred = 10
	step(five, "Deferred mail: back to normal on mail.example.com")
}

func TestQueueScanIsShared(t *testing.T) {
	scans := 0
	m := &resourceMonitor{levels: map[string]int{}, list: func(q queue.QueueType) ([]queue.Message, error) {
		if q == queue.Active {
			scans++
		}
		return nil, errors.New("backend down")
	}}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for range 10 {
		items := m.attention(now)
		require.Len(t, items, 1)
		require.Equal(t, attentionUnknown, items[0].Severity)
	}
	require.Equal(t, 1, scans, "every dashboard poll walked the queue")
	m.attention(now.Add(resourceWatchEvery))
	require.Equal(t, 2, scans)
}

func TestAttentionWorstFirst(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	s := &Server{configPath: filepath.Join(dir, "elemta.toml"), abuse: abuse.New("test", "", nil),
		mainConfig: &MainConfig{TLSCertFile: filepath.Join(dir, "missing.pem")},
		monitor: &resourceMonitor{levels: map[string]int{}, diskPaths: []string{dir},
			disk: func(string) (diskUsage, error) { return diskUsage{SpacePercent: 88}, nil },
			list: func(queue.QueueType) ([]queue.Message, error) { return nil, errors.New("down") }}}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "backup-status.json"), []byte("{broken"), 0o600))
	got := [][2]string{}
	for _, i := range s.attention(context.Background(), now) {
		got = append(got, [2]string{i.Severity, i.Title})
	}
	require.Equal(t, [][2]string{
		{attentionCritical, "TLS certificate"},
		{attentionWarning, "Disk space"},
		{attentionUnknown, "Mail queue"},
		{attentionUnknown, "Backups"},
		{attentionInfo, "Alert emails"},
	}, got)
}

func TestReadDiskUsage(t *testing.T) {
	d, err := readDiskUsage(t.TempDir())
	require.NoError(t, err)
	require.NotEmpty(t, d.Device)
	require.True(t, d.SpacePercent >= 0 && d.SpacePercent <= 100)
	_, err = readDiskUsage(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

func TestAttentionNeedsSystemAdministrator(t *testing.T) {
	base, _ := startProvisionAPI(t)
	code, body := userRequest(t, "GET", base+"/api/attention", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"items"`)
	code, body = userRequest(t, "GET", base+"/api/attention", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code, body)
	res, err := http.Get(base + "/api/attention")
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}
