package logship

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

const (
	shipBatch   = 500
	shipEvery   = 2 * time.Second
	shipLease   = time.Minute
	shipMaxWait = time.Minute
	// shipBatches bounds one round, so settings are read again in a backlog.
	shipBatches = 20
	fileName    = "log-shipping.json"
)

// saved is the file beside the configuration. The credential is kept with
// the origin it was given for, and never sent to another.
type saved struct {
	Settings   Settings   `json:"settings"`
	Credential Credential `json:"credential"`
	Origin     string     `json:"origin,omitempty"`
}

// Shipper is the console's end: the settings, and from the stream to the
// destination.
type Shipper struct {
	path  string
	addr  string
	log   *slog.Logger
	owner string
	// destinations are the only places anything is sent.
	destinations []string

	mu     sync.Mutex
	client valkey.Client
}

// NewShipper keeps its settings in dir and sends only to destinations.
func NewShipper(dir, addr string, destinations []string, log *slog.Logger) *Shipper {
	if log == nil {
		log = slog.Default()
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	s := &Shipper{addr: addr, destinations: slices.Clone(destinations), log: log.With("component", "log-shipping"), owner: hex.EncodeToString(id[:])}
	if dir != "" {
		s.path = filepath.Join(dir, fileName)
	}
	return s
}

func (s *Shipper) valkey() (valkey.Client, error) {
	if s.addr == "" {
		return nil, errors.New("log shipping needs Valkey, which carries the logs from each service")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		c, err := valkeyaddr.NewClient(s.addr, nil)
		if err != nil {
			return nil, err
		}
		s.client = c
	}
	return s.client, nil
}

func (s *Shipper) load() (saved, error) {
	var f saved
	if s.path != "" {
		data, err := os.ReadFile(s.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return f, err
		default:
			if err := json.Unmarshal(data, &f); err != nil {
				return f, fmt.Errorf("reading %s: %w", s.path, err)
			}
		}
	}
	f.Settings = f.Settings.WithDefaults()
	if f.Origin != f.Settings.origin() {
		f.Credential = Credential{}
	}
	return f, nil
}

// Settings returns what is saved, and whether a credential is with it.
func (s *Shipper) Settings() (Settings, bool, error) {
	f, err := s.load()
	return f.Settings, f.Credential.set(), err
}

// Destinations are the URLs logs may be sent to.
func (s *Shipper) Destinations() []string {
	return append([]string{}, s.destinations...)
}

var errUnlisted = invalid{errors.New("that destination isn't allowed: list its URL in " + DestinationsEnv + " on the admin console and restart it")}

// approved finds url in the operator's list and returns the list's own copy,
// which is the one requests are made to.
func (s *Shipper) approved(url string) (string, error) {
	for _, d := range s.destinations {
		if d == url {
			return d, nil
		}
	}
	return "", errUnlisted
}

func (s *Shipper) sinkFor(f saved) (*sink, error) {
	base, err := s.approved(f.Settings.URL)
	if err != nil {
		return nil, err
	}
	return newSink(base, f.Settings, f.Credential), nil
}

// merge is the file as it would be. A nil credential keeps the saved one,
// if the destination is the same.
func (s *Shipper) merge(next Settings, c *Credential) (saved, error) {
	next = next.WithDefaults()
	if err := next.Validate(); err != nil {
		return saved{}, invalid{err}
	}
	f, err := s.load()
	if err != nil {
		return f, err
	}
	if c != nil {
		if err := c.valid(); err != nil {
			return f, invalid{err}
		}
		f.Credential, f.Origin = *c, next.origin()
	} else if f.Origin != next.origin() {
		f.Credential, f.Origin = Credential{}, next.origin()
	}
	f.Settings = next
	return f, nil
}

type invalid struct{ error }

// IsInvalid reports whether err is the caller's to correct.
func IsInvalid(err error) bool {
	var v invalid
	return errors.As(err, &v)
}

// Save validates and stores the settings, and tells the services.
func (s *Shipper) Save(ctx context.Context, next Settings, c *Credential) error {
	if s.path == "" {
		return errors.New("log shipping needs a configuration directory to keep its settings in")
	}
	if next.Enabled && s.addr == "" {
		return invalid{errors.New("log shipping needs Valkey, which carries the logs from each service")}
	}
	f, err := s.merge(next, c)
	if err != nil {
		return err
	}
	// Only when on: switching off has to work after the list has changed.
	if f.Settings.Enabled {
		if _, err := s.approved(f.Settings.URL); err != nil {
			return err
		}
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), fileName+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	// CreateTemp makes it 0600: it can hold a password.
	_, err = tmp.Write(data)
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	if client, err := s.valkey(); err == nil {
		ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
		defer cancel()
		if err := s.publish(ctx, client, f.Settings); err != nil {
			s.log.Warn("Log shipping settings saved but not yet published", "error", err)
		}
		// A new destination starts with a clean record of failures.
		_ = client.Do(ctx, client.B().Hdel().Key(keyStatus).Field("last_error", "failing_since", "reject_reason").Build()).Error()
	}
	return nil
}

// Test sends one line to a destination as it would be saved, now.
func (s *Shipper) Test(ctx context.Context, next Settings, c *Credential) error {
	next.Enabled = true
	f, err := s.merge(next, c)
	if err != nil {
		return err
	}
	to, err := s.sinkFor(f)
	if err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	now := time.Now().UTC()
	line, err := json.Marshal(map[string]any{"time": now.Format(time.RFC3339Nano), "level": "INFO", "msg": "Elemta log shipping test", "event_type": "log_shipping_test"})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	out, err := to.send(ctx, []entry{newEntry(strconv.FormatInt(now.UnixNano(), 10), "admin", host, string(line), now)})
	if err != nil {
		return err
	}
	if out.rejected > 0 {
		return errors.New("the test line was refused: " + out.reason)
	}
	return nil
}

func (s *Shipper) publish(ctx context.Context, client valkey.Client, set Settings) error {
	raw, err := json.Marshal(policy{Enabled: set.Enabled, MinLevel: set.MinLevel, IncludeSubjects: set.IncludeSubjects})
	if err != nil {
		return err
	}
	if err := client.Do(ctx, client.B().Set().Key(keyPolicy).Value(string(raw)).Build()).Error(); err != nil {
		return err
	}
	if !set.Enabled {
		return client.Do(ctx, client.B().Del().Key(keyStream).Build()).Error()
	}
	return nil
}

// Run ships until ctx ends.
func (s *Shipper) Run(ctx context.Context) {
	if s.addr == "" || s.path == "" {
		return
	}
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.client != nil {
			s.client.Close()
			s.client = nil
		}
	}()
	var (
		out      *sink
		using    saved
		failures int
		unread   bool
	)
	wait := time.Duration(0)
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		wait = shipEvery
		f, err := s.load()
		if err != nil {
			if !unread {
				s.log.Error("Log shipping settings can't be read", "error", err)
				unread = true
			}
			continue
		}
		unread = false
		client, err := s.valkey()
		if err != nil {
			continue
		}
		// Every round, so a Valkey that lost its data learns it again.
		c, cancel := context.WithTimeout(ctx, valkeyTimeout)
		err = s.publish(c, client, f.Settings)
		cancel()
		if err != nil || !f.Settings.Enabled {
			out, failures = nil, 0
			continue
		}
		if out == nil || using != f {
			// Checked here too: the file can outlive the list it was saved under.
			next, err := s.sinkFor(f)
			if err != nil {
				out = nil
				if failures == 0 {
					s.log.Warn("Log shipping has nowhere allowed to send; logs wait in Valkey", "error", err)
					failures = 1
				}
				if err := s.record(ctx, client, delivery{}, err); err != nil {
					s.log.Debug("Log shipping's status wasn't recorded", "error", err)
				}
				continue
			}
			out, using, failures = next, f, 0
		}
		err = s.ship(ctx, client, out)
		switch {
		case ctx.Err() != nil:
		case err != nil:
			failures++
			wait = min(shipMaxWait, shipEvery<<min(failures, 5))
			if failures == 1 {
				s.log.Warn("Log shipping is failing; logs wait in Valkey", "error", err)
			}
		case failures > 0:
			failures = 0
			s.log.Info("Log shipping is working again")
		}
	}
}

// ship empties the stream. One console does at a time.
func (s *Shipper) ship(ctx context.Context, client valkey.Client, out *sink) error {
	lease := func(renew bool) bool {
		c, cancel := context.WithTimeout(ctx, valkeyTimeout)
		defer cancel()
		if renew {
			if holder, err := client.Do(c, client.B().Get().Key(keyLock).Build()).ToString(); err != nil || holder != s.owner {
				return false
			}
			return client.Do(c, client.B().Set().Key(keyLock).Value(s.owner).Px(shipLease).Build()).Error() == nil
		}
		return client.Do(c, client.B().Set().Key(keyLock).Value(s.owner).Nx().Px(shipLease).Build()).Error() == nil
	}
	if !lease(false) {
		return nil
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), valkeyTimeout)
		defer cancel()
		if holder, err := client.Do(c, client.B().Get().Key(keyLock).Build()).ToString(); err == nil && holder == s.owner {
			_ = client.Do(c, client.B().Del().Key(keyLock).Build()).Error()
		}
	}()
	for range shipBatches {
		c, cancel := context.WithTimeout(ctx, valkeyTimeout)
		rows, err := client.Do(c, client.B().Xrange().Key(keyStream).Start("-").End("+").Count(shipBatch).Build()).AsXRange()
		cancel()
		if err != nil {
			if valkey.IsValkeyNil(err) {
				return nil
			}
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		batch := make([]entry, 0, len(rows))
		for _, row := range rows {
			queued := time.Now()
			ms, _, _ := strings.Cut(row.ID, "-")
			if n, err := strconv.ParseInt(ms, 10, 64); err == nil {
				queued = time.UnixMilli(n)
			}
			batch = append(batch, newEntry(row.ID, row.FieldValues["s"], row.FieldValues["h"], row.FieldValues["e"], queued))
		}
		result, sendErr := out.send(ctx, batch)
		if err := s.record(ctx, client, result, sendErr); err != nil {
			return errors.Join(sendErr, err)
		}
		if sendErr != nil {
			return sendErr
		}
		if len(rows) < shipBatch || !lease(true) {
			return nil
		}
	}
	return nil
}

func (s *Shipper) record(ctx context.Context, client valkey.Client, d delivery, sendErr error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), valkeyTimeout)
	defer cancel()
	b := client.B
	var cmds valkey.Commands
	if len(d.done) > 0 {
		cmds = append(cmds, b().Xdel().Key(keyStream).Id(d.done...).Build())
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if d.sent > 0 {
		cmds = append(cmds,
			b().Hincrby().Key(keyStatus).Field("sent").Increment(int64(d.sent)).Build(),
			b().Hset().Key(keyStatus).FieldValue().FieldValue("last_success", now).Build())
	}
	if d.rejected > 0 {
		cmds = append(cmds,
			b().Hincrby().Key(keyStatus).Field("rejected").Increment(int64(d.rejected)).Build(),
			b().Hset().Key(keyStatus).FieldValue().FieldValue("reject_reason", d.reason).Build())
	}
	if sendErr != nil {
		cmds = append(cmds,
			b().Hset().Key(keyStatus).FieldValue().FieldValue("last_error", clip(sendErr.Error())).Build(),
			b().Hsetnx().Key(keyStatus).Field("failing_since").Value(now).Build())
	} else {
		cmds = append(cmds, b().Hdel().Key(keyStatus).Field("last_error", "failing_since").Build())
	}
	for _, r := range client.DoMulti(ctx, cmds...) {
		if err := r.Error(); err != nil {
			return err
		}
	}
	return nil
}

// Status reads how it's going.
func (s *Shipper) Status(ctx context.Context) (Status, error) {
	var out Status
	f, err := s.load()
	if err != nil {
		return out, err
	}
	out.CredentialSet = f.Credential.set()
	if s.addr == "" {
		return out, nil
	}
	client, err := s.valkey()
	if err != nil {
		return out, nil // not available, which the zero value says
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	h, err := client.Do(ctx, client.B().Hgetall().Key(keyStatus).Build()).AsStrMap()
	if err != nil {
		return out, nil
	}
	if out.Waiting, err = client.Do(ctx, client.B().Xlen().Key(keyStream).Build()).AsInt64(); err != nil {
		return out, nil
	}
	out.Available = true
	number := func(key string) int64 {
		n, err := strconv.ParseInt(h[key], 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	when := func(key string) *time.Time {
		if t, err := time.Parse(time.RFC3339, h[key]); err == nil {
			return &t
		}
		return nil
	}
	out.Sent, out.Dropped, out.Rejected = number("sent"), number("dropped"), number("rejected")
	out.LastSuccess, out.FailingSince, out.LastDropped = when("last_success"), when("failing_since"), when("last_dropped")
	out.LastError, out.RejectReason = h["last_error"], h["reject_reason"]
	return out, nil
}
