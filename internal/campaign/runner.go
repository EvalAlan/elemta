package campaign

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/queue"
)

const (
	// DefaultRatePerMinute is used when a campaign does not set one. A default
	// of "as fast as possible" is the setting nobody notices until a bulk run
	// has buried every other message in the queue.
	DefaultRatePerMinute = 600
	// MaxRatePerMinute bounds what the UI can ask for.
	MaxRatePerMinute = 60000
)

// Enqueuer is the part of the queue manager a campaign needs. Narrowing it to
// this keeps the runner testable without a queue on disk.
type Enqueuer interface {
	EnqueueMessage(from string, to []string, subject string, data []byte, priority queue.Priority, receivedAt time.Time) (string, error)
}

// Store holds campaigns. In-memory: a campaign is an operator action in
// progress, not a system of record, and persisting it would mean a schema and a
// migration for something usually measured in minutes. Anything already handed
// to the queue survives a restart because the queue is durable — what is lost
// is the unsent remainder, which the operator can resend.
type Store struct {
	mu        sync.RWMutex
	campaigns map[string]*Campaign
	order     []string
}

func NewStore() *Store {
	return &Store{campaigns: make(map[string]*Campaign)}
}

func (s *Store) Put(c *Campaign) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.campaigns[c.ID]; !exists {
		s.order = append(s.order, c.ID)
	}
	s.campaigns[c.ID] = c
}

func (s *Store) Get(id string) (*Campaign, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.campaigns[id]
	return c, ok
}

// List returns campaigns newest first.
func (s *Store) List() []*Campaign {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Campaign, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		if c, ok := s.campaigns[s.order[i]]; ok {
			out = append(out, c.Clone())
		}
	}
	return out
}

func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.campaigns[id]; !ok {
		return false
	}
	delete(s.campaigns, id)
	for i, existing := range s.order {
		if existing == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return true
}

// SuppressionList is the part of the suppression store a campaign needs.
//
// Narrowed to one question so the campaign package does not depend on how the
// list is stored, and so a deployment without one simply answers "no".
type SuppressionList interface {
	// SuppressedWithReason answers whether an address must not be mailed, and
	// why. It does not return an error: a list that cannot be read must not
	// stop a campaign, because failing closed here would halt all sending
	// because of a locked database.
	SuppressedWithReason(ctx context.Context, address string) (bool, string)
}

// Runner sends campaigns, one goroutine per running campaign.
type Runner struct {
	store       *Store
	queue       Enqueuer
	hostname    string
	logger      *slog.Logger
	suppression SuppressionList

	mu sync.Mutex
	// runs is keyed by campaign ID. The token distinguishes one run of a
	// campaign from the next: a paused run's goroutine can outlive the call
	// that paused it, and without the token its cleanup would cancel the run
	// that replaced it — so a resumed campaign would stop again immediately,
	// with nothing to show why.
	runs      map[string]runHandle
	nextToken uint64
}

type runHandle struct {
	cancel context.CancelFunc
	token  uint64
}

// SetSuppressionList attaches the list of addresses that must not be mailed.
// Optional: without it a campaign sends to everyone on its list, which is the
// behaviour before suppression existed.
func (r *Runner) SetSuppressionList(list SuppressionList) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppression = list
}

func NewRunner(store *Store, q Enqueuer, hostname string, logger *slog.Logger) *Runner {
	return &Runner{
		store:    store,
		queue:    q,
		hostname: hostname,
		logger:   logger,
		runs:     make(map[string]runHandle),
	}
}

// Start begins or resumes sending.
//
// It returns as soon as the campaign is running. Enqueuing tens of thousands of
// messages inside the request that asked for it would hold the connection open
// for hours and give no way to watch or stop it.
func (r *Runner) Start(c *Campaign) error {
	c.mu.Lock()
	if !c.CanStart() {
		state := c.State
		c.mu.Unlock()
		return fmt.Errorf("a campaign in state %q cannot be started", state)
	}
	if err := c.Validate(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.State = StateRunning
	c.UpdatedAt = time.Now().UTC()
	if c.StartedAt == nil {
		now := time.Now().UTC()
		c.StartedAt = &now
	}
	rate := c.RatePerMinute
	c.mu.Unlock()

	if rate <= 0 {
		rate = DefaultRatePerMinute
	}
	if rate > MaxRatePerMinute {
		rate = MaxRatePerMinute
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	// Starting an already-running campaign would send every remaining
	// recipient twice.
	if _, running := r.runs[c.ID]; running {
		r.mu.Unlock()
		cancel()
		return fmt.Errorf("campaign %s is already running", c.ID)
	}
	r.nextToken++
	token := r.nextToken
	r.runs[c.ID] = runHandle{cancel: cancel, token: token}
	r.mu.Unlock()

	go r.run(ctx, c, rate, token)
	return nil
}

// Pause stops sending, leaving the campaign resumable from where it stopped.
func (r *Runner) Pause(c *Campaign) error {
	c.mu.Lock()
	if c.State != StateRunning {
		state := c.State
		c.mu.Unlock()
		return fmt.Errorf("a campaign in state %q cannot be paused", state)
	}
	c.State = StatePaused
	c.UpdatedAt = time.Now().UTC()
	c.mu.Unlock()

	r.stop(c.ID)
	return nil
}

// Cancel stops sending for good. Messages already handed to the queue are not
// recalled — they have been accepted for delivery, and pretending otherwise
// would be a lie about where the mail is.
func (r *Runner) Cancel(c *Campaign) error {
	c.mu.Lock()
	if c.State == StateCompleted || c.State == StateCancelled {
		state := c.State
		c.mu.Unlock()
		return fmt.Errorf("a campaign in state %q cannot be cancelled", state)
	}
	c.State = StateCancelled
	c.UpdatedAt = time.Now().UTC()
	c.mu.Unlock()

	r.stop(c.ID)
	return nil
}

// stop ends whatever run is current for a campaign. Used by Pause and Cancel,
// where the intent is to stop the campaign whichever run is active.
func (r *Runner) stop(id string) {
	r.mu.Lock()
	handle, ok := r.runs[id]
	delete(r.runs, id)
	r.mu.Unlock()
	if ok {
		handle.cancel()
	}
}

// finish clears a run's own registration, and only its own. A goroutine that
// is shutting down must not disturb the run that has already replaced it.
func (r *Runner) finish(id string, token uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handle, ok := r.runs[id]; ok && handle.token == token {
		delete(r.runs, id)
	}
}

// StopAll ends every running campaign, for shutdown.
func (r *Runner) StopAll() {
	r.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(r.runs))
	for id, handle := range r.runs {
		cancels = append(cancels, handle.cancel)
		delete(r.runs, id)
	}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// run enqueues the remaining recipients at the configured rate.
func (r *Runner) run(ctx context.Context, c *Campaign, ratePerMinute int, token uint64) {
	defer r.finish(c.ID, token)

	interval := time.Minute / time.Duration(ratePerMinute)
	if interval <= 0 {
		interval = time.Microsecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	r.logger.Info("Campaign started",
		"campaign_id", c.ID,
		"name", c.Name,
		"recipients", c.Total(),
		"rate_per_minute", ratePerMinute,
	)

	for {
		// Resume picks up after everything already attempted, which is why
		// Sent and Failed only ever move forward.
		c.mu.Lock()
		// Skipped counts towards progress as much as sent and failed do:
		// without it the loop re-reads the suppressed recipient forever,
		// skipping the same address until something cancels the campaign.
		index := c.Sent + c.Failed + c.Skipped
		if c.State != StateRunning || index >= len(c.Recipients) {
			done := index >= len(c.Recipients)
			if done && c.State == StateRunning {
				c.State = StateCompleted
				now := time.Now().UTC()
				c.CompletedAt = &now
				c.UpdatedAt = now
			}
			state := c.State
			sent, failed := c.Sent, c.Failed
			c.mu.Unlock()
			c.mu.Lock()
			skipped := c.Skipped
			c.mu.Unlock()
			r.logger.Info("Campaign finished",
				"campaign_id", c.ID, "state", state, "sent", sent, "failed", failed,
				"skipped_suppressed", skipped)
			return
		}
		recipient := c.Recipients[index]
		c.mu.Unlock()

		// Checked before the tick, not after: a suppressed address costs no
		// send, so it should not consume a slot in the rate limit either.
		// Otherwise a list that is mostly suppressed would take as long to skip
		// as it would have taken to send.
		if reason, skip := r.suppressed(ctx, recipient.Email); skip {
			c.mu.Lock()
			c.Skipped++
			c.UpdatedAt = time.Now().UTC()
			c.mu.Unlock()
			r.logger.Info("Campaign recipient skipped",
				"event_type", "suppression",
				"campaign_id", c.ID, "recipient", recipient.Email, "reason", reason)
			continue
		}

		select {
		case <-ctx.Done():
			r.logger.Info("Campaign stopped", "campaign_id", c.ID)
			return
		case <-ticker.C:
		}

		if err := r.sendOne(c, recipient); err != nil {
			c.mu.Lock()
			c.Failed++
			c.LastError = err.Error()
			c.UpdatedAt = time.Now().UTC()
			c.mu.Unlock()
			r.logger.Warn("Campaign recipient failed",
				"campaign_id", c.ID, "recipient", recipient.Email, "error", err)
			continue
		}

		c.mu.Lock()
		c.Sent++
		c.UpdatedAt = time.Now().UTC()
		c.mu.Unlock()
	}
}

// suppressed reports whether an address is on the suppression list.
func (r *Runner) suppressed(ctx context.Context, address string) (string, bool) {
	r.mu.Lock()
	list := r.suppression
	r.mu.Unlock()
	if list == nil {
		return "", false
	}
	yes, reason := list.SuppressedWithReason(ctx, address)
	return reason, yes
}

// sendOne renders and enqueues a single copy.
func (r *Runner) sendOne(c *Campaign, recipient Recipient) error {
	c.mu.Lock()
	snapshot := c.cloneLocked()
	c.mu.Unlock()

	body, err := BuildMessage(snapshot, recipient, r.hostname)
	if err != nil {
		return fmt.Errorf("build message: %w", err)
	}
	sender, err := EnvelopeSender(snapshot.From)
	if err != nil {
		return err
	}

	// Bulk mail queues at low priority so a campaign cannot overtake ordinary
	// transactional mail waiting behind it.
	_, err = r.queue.EnqueueMessage(
		sender,
		[]string{recipient.Email},
		Merge(snapshot.Subject, recipient.Vars),
		body,
		queue.PriorityLow,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	return nil
}

// SendTest enqueues a single copy to one address, using the first recipient's
// variables so merge fields render the way they will in the real send.
func (r *Runner) SendTest(c *Campaign, to string) error {
	recipient := Recipient{Email: to}
	if len(c.Recipients) > 0 {
		recipient.Vars = c.Recipients[0].Vars
	}

	snapshot := c.Clone()
	snapshot.Subject = "[TEST] " + snapshot.Subject
	body, err := BuildMessage(snapshot, recipient, r.hostname)
	if err != nil {
		return err
	}
	sender, err := EnvelopeSender(snapshot.From)
	if err != nil {
		return err
	}
	_, err = r.queue.EnqueueMessage(
		sender, []string{to}, snapshot.Subject, body, queue.PriorityNormal, time.Now(),
	)
	return err
}
