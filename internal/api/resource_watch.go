package api

// Disk and queue alerts.
//
// A full disk stops a mail server completely, and a queue that stops moving
// does it quietly: mail is accepted and goes nowhere. The admin process
// checks both every few minutes and emails the alert addresses, as it does
// for backups. Those emails travel through this same server, so they warn of
// an outage that is coming; one that has happened needs a check from outside.

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/queue"
)

const (
	resourceWatchEvery = 5 * time.Minute
	// resourceWatchFirst lets the queue drain what a restart left in it.
	resourceWatchFirst = time.Minute
)

// limit is where a measurement becomes a problem, and the lower value where
// it stops being one, so that a value sitting on the line doesn't email on
// every check.
type limit struct {
	warn, warnClear         float64
	critical, criticalClear float64
}

var (
	diskLimit      = limit{warn: 85, warnClear: 82, critical: 95, criticalClear: 92} // percent
	activeAgeLimit = limit{warn: 15, warnClear: 10, critical: 60, criticalClear: 45} // minutes
	deferredLimit  = limit{warn: 100, warnClear: 80, critical: 1000, criticalClear: 800}
)

// level is v's level, given the one before.
func (l limit) level(v float64, before int) int {
	switch {
	case v >= l.critical || before == 2 && v >= l.criticalClear:
		return 2
	case v >= l.warn || before > 0 && v >= l.warnClear:
		return 1
	}
	return 0
}

type diskUsage struct {
	Path         string
	Device       string
	SpacePercent float64
	InodePercent float64
	FreeBytes    float64
}

type queueReading struct {
	At time.Time
	// ActiveSince is when the message that has waited longest entered the
	// active queue or last made progress there. Its creation won't do: a
	// retry of a two-day-old deferral has just arrived, and isn't stuck.
	ActiveSince time.Time
	Deferred    int
}

// resource is one thing measured.
type resource struct {
	key, title, detail, view string
	value                    float64
	limit                    limit
	since                    time.Time
}

// resourceMonitor holds what the checks share with the dashboard.
type resourceMonitor struct {
	disk      func(string) (diskUsage, error)
	list      func(queue.QueueType) ([]queue.Message, error)
	diskPaths []string

	mu       sync.Mutex
	scanned  time.Time
	queue    queueReading
	queueErr error
	levels   map[string]int
}

func newResourceMonitor(manager *queue.Manager, queueDir, configPath string) *resourceMonitor {
	m := &resourceMonitor{disk: readDiskUsage, levels: map[string]int{}}
	if manager != nil {
		m.list = manager.ListMessages
	}
	if queueDir != "" {
		// A backend other than files may never create the directory.
		if _, err := os.Stat(queueDir); err == nil {
			m.diskPaths = append(m.diskPaths, queueDir)
		}
	}
	if configPath != "" {
		m.diskPaths = append(m.diskPaths, filepath.Dir(configPath))
	}
	return m
}

// queueState lists the queue at most once per interval however many
// dashboards are open: a listing decodes every message in it.
func (m *resourceMonitor) queueState(now time.Time) (queueReading, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.scanned.IsZero() && now.Sub(m.scanned) < resourceWatchEvery-time.Second {
		return m.queue, m.queueErr
	}
	m.scanned = now
	m.queue, m.queueErr = m.scanQueue(now)
	return m.queue, m.queueErr
}

func (m *resourceMonitor) scanQueue(now time.Time) (queueReading, error) {
	out := queueReading{At: now}
	active, err := m.list(queue.Active)
	if err != nil {
		return out, err
	}
	for _, msg := range active {
		since := msg.UpdatedAt
		if since.IsZero() {
			since = msg.CreatedAt
		}
		if !since.IsZero() && (out.ActiveSince.IsZero() || since.Before(out.ActiveSince)) {
			out.ActiveSince = since
		}
	}
	deferred, err := m.list(queue.Deferred)
	if err != nil {
		return out, err
	}
	out.Deferred = len(deferred)
	return out, nil
}

// resources measures everything, and names what couldn't be measured.
func (m *resourceMonitor) resources(now time.Time) (out []resource, failed []attentionItem) {
	var devices []string
	for _, path := range m.diskPaths {
		d, err := m.disk(path)
		if err != nil {
			slog.Warn("Disk check failed", "path", path, "error", err)
			failed = append(failed, couldNotCheck("Disk space", "The space left at "+path+" couldn't be read.", "health"))
			continue
		}
		if slices.Contains(devices, d.Device) {
			continue
		}
		devices = append(devices, d.Device)
		out = append(out,
			resource{key: "space:" + d.Device, title: "Disk space", view: "health", limit: diskLimit, value: d.SpacePercent,
				detail: fmt.Sprintf("The disk holding %s is %.0f%% full, with %s free. Mail stops when it fills.", path, math.Floor(d.SpacePercent), freeSpace(d.FreeBytes))},
			resource{key: "inodes:" + d.Device, title: "Disk file slots", view: "health", limit: diskLimit, value: d.InodePercent,
				detail: fmt.Sprintf("%.0f%% of the inodes on the disk holding %s are used. When they run out no file can be created, whatever space is left.", math.Floor(d.InodePercent), path)})
	}
	if m.list == nil {
		return out, failed
	}
	q, err := m.queueState(now)
	if err != nil {
		slog.Warn("Queue check failed", "error", err)
		return out, append(failed, couldNotCheck("Mail queue", "The queue couldn't be listed.", "queues"))
	}
	waited := 0.0
	if !q.ActiveSince.IsZero() {
		waited = q.At.Sub(q.ActiveSince).Minutes()
	}
	return append(out,
		resource{key: "active", title: "Queue not moving", view: "queues", limit: activeAgeLimit, value: waited, since: q.ActiveSince,
			detail: fmt.Sprintf("A message has waited %.0f minutes in the active queue, where mail normally leaves in seconds.", math.Floor(waited))},
		resource{key: "deferred", title: "Deferred mail", view: "queues", limit: deferredLimit, value: float64(q.Deferred),
			detail: fmt.Sprintf("%d messages are waiting to be retried.", q.Deferred)},
	), failed
}

func (m *resourceMonitor) levelBefore(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.levels[key]
}

func (m *resourceMonitor) setLevel(key string, level int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.levels[key] = level
}

// attention is the resources that are over their limits now, worded as the
// emails are. A problem that was alerted on stays until it has cleared.
func (m *resourceMonitor) attention(now time.Time) []attentionItem {
	resources, out := m.resources(now)
	for _, r := range resources {
		level := r.limit.level(r.value, m.levelBefore(r.key))
		if level == 0 {
			continue
		}
		item := attentionItem{Severity: severityOf(level), Title: r.title, Detail: r.detail, View: r.view}
		if !r.since.IsZero() {
			item.Since = r.since.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out
}

type resourceNotice struct{ subject, body string }

// check returns the emails to send. Something that couldn't be measured
// keeps its level: it neither raises a problem nor announces a recovery.
func (m *resourceMonitor) check(alerts map[string]*alerter, host string, now time.Time) []resourceNotice {
	resources, _ := m.resources(now)
	var out []resourceNotice
	for _, r := range resources {
		a := alerts[r.key]
		if a == nil {
			a = &alerter{}
			alerts[r.key] = a
		}
		level := r.limit.level(r.value, m.levelBefore(r.key))
		m.setLevel(r.key, level)
		send, recovered := a.observe(level, now)
		switch {
		case !send:
		case recovered:
			out = append(out, resourceNotice{r.title + ": back to normal on " + host,
				"The problem reported earlier has cleared.\n\n" + r.detail + "\n"})
		default:
			subject := r.title + " warning on " + host
			if level == 2 {
				subject = r.title + " critical on " + host
			}
			out = append(out, resourceNotice{subject,
				r.detail + "\n\nThe Dashboard in the admin console shows the current state. This is repeated daily until it clears.\n"})
		}
	}
	return out
}

func freeSpace(bytes float64) string {
	if gib := bytes / (1 << 30); gib >= 1 {
		return fmt.Sprintf("%.1f GiB", gib)
	}
	return fmt.Sprintf("%.0f MiB", bytes/(1<<20))
}

// watchResources runs the checks until stop closes.
func (s *Server) watchResources(stop <-chan struct{}) {
	if s.abuse == nil || s.monitor == nil {
		return
	}
	host := s.alertHost()
	alerts := map[string]*alerter{}
	timer := time.NewTimer(resourceWatchFirst)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		for _, n := range s.monitor.check(alerts, host, time.Now()) {
			slog.Warn("Resource alert", "subject", n.subject)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if !s.abuse.Notify(ctx, n.subject, n.body) {
				slog.Warn("Resource alert not emailed: set alert addresses in Settings > Alert emails")
			}
			cancel()
		}
		timer.Reset(resourceWatchEvery)
	}
}
