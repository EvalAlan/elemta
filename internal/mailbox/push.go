package mailbox

// Web Push: notifications on people's phones and computers when new mail
// reaches the inbox and when an event reminder comes due, even with the
// webmail closed.
//
// This service sends them because it is the part that sees every delivery
// and can act without anyone signed in. The webmail registers each browser
// that asks (security_api.go), and publishes upcoming reminders the same way
// it publishes free/busy times, since only it can read and expand a
// calendar. Messages are encrypted for the browser (internal/webpush), so
// the push services carrying them can't read them.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"github.com/lib/pq"

	"github.com/EvalAlan/elemta/internal/webpush"
)

const (
	// maxPushDevices is how many browsers one account can have notified.
	maxPushDevices = 20
	// maxPushReminders bounds what the webmail may publish for one account.
	maxPushReminders = 500
	// pushGiveUp drops a subscription after this many failures in a row,
	// one the push service neither accepts nor says is gone.
	pushGiveUp = 50
	// reminderLate is how late a reminder may still go out, after a restart
	// or an outage.
	reminderLate = 15 * time.Minute
)

// pushMailDelay gathers a burst of deliveries into one notification.
var pushMailDelay = 2 * time.Second

// PushDevice is one subscribed browser, as the settings page lists it.
type PushDevice struct {
	ID        int64      `json:"id"`
	Endpoint  string     `json:"endpoint"`
	Label     string     `json:"label"`
	Mail      string     `json:"mail"` // all, primary or off
	Reminders bool       `json:"reminders"`
	Preview   bool       `json:"preview"`
	Created   time.Time  `json:"created"`
	LastSent  *time.Time `json:"last_sent,omitempty"`
}

// PushSubscribe is what the webmail sends when a browser turns
// notifications on, or changes what it wants.
type PushSubscribe struct {
	Endpoint  string `json:"endpoint"`
	P256dh    string `json:"p256dh"`
	Auth      string `json:"auth"`
	Label     string `json:"label"`
	Mail      string `json:"mail"`
	Reminders bool   `json:"reminders"`
	Preview   bool   `json:"preview"`
	// Contact is the webmail's address, which push services are told is
	// where to reach whoever runs this server.
	Contact string `json:"contact"`
}

// PushReminder is one upcoming reminder.
type PushReminder struct {
	Key    string    `json:"key"`
	At     time.Time `json:"at"`
	Starts time.Time `json:"start"`
	Title  string    `json:"title"`
	Body   string    `json:"body"`
	URL    string    `json:"url"`
}

var errBadPush = &requestError{"invalid push subscription"}

type pushRow struct {
	PushDevice
	sub     webpush.Subscription
	contact string
}

func (e *Engine) pushRows(ctx context.Context, account string) ([]pushRow, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT id,endpoint,p256dh,auth,label,mail,reminders,preview,contact,created,last_sent
		FROM mailbox_push_subscriptions WHERE account=$1 ORDER BY created`, account)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []pushRow
	for rows.Next() {
		var r pushRow
		var last sql.NullTime
		if err := rows.Scan(&r.ID, &r.Endpoint, &r.sub.P256dh, &r.sub.Auth, &r.Label, &r.Mail, &r.Reminders, &r.Preview, &r.contact, &r.Created, &last); err != nil {
			return nil, err
		}
		r.sub.Endpoint = r.Endpoint
		if last.Valid {
			r.LastSent = &last.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PushDevices lists the browsers an account has notified.
func (e *Engine) PushDevices(ctx context.Context, account string) ([]PushDevice, error) {
	rows, err := e.pushRows(ctx, account)
	out := make([]PushDevice, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.PushDevice)
	}
	return out, err
}

func validPushContact(c string) string {
	u, err := url.Parse(c)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(c) > 200 {
		return ""
	}
	return "https://" + u.Host
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// PutPushSubscription saves a browser's subscription, or updates what it
// wants. An endpoint someone else had moves to this account.
func (e *Engine) PutPushSubscription(ctx context.Context, account string, in PushSubscribe, check func(string) error) (int64, error) {
	sub := webpush.Subscription{Endpoint: in.Endpoint, P256dh: in.P256dh, Auth: in.Auth}
	if check(in.Endpoint) != nil || sub.Valid() != nil {
		return 0, errBadPush
	}
	switch in.Mail {
	case "all", "primary", "off":
	default:
		return 0, errBadPush
	}
	var id int64
	err := e.tx(ctx, account, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `INSERT INTO mailbox_push_subscriptions(account,endpoint,p256dh,auth,label,mail,reminders,preview,contact)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (endpoint) DO UPDATE SET account=EXCLUDED.account,p256dh=EXCLUDED.p256dh,auth=EXCLUDED.auth,label=EXCLUDED.label,
				mail=EXCLUDED.mail,reminders=EXCLUDED.reminders,preview=EXCLUDED.preview,contact=EXCLUDED.contact,failures=0
			RETURNING id`,
			account, in.Endpoint, in.P256dh, in.Auth, clip(in.Label, 80), in.Mail, in.Reminders, in.Preview, validPushContact(in.Contact)).Scan(&id)
		if err != nil {
			return err
		}
		// The oldest go first when there are too many.
		_, err = tx.ExecContext(ctx, `DELETE FROM mailbox_push_subscriptions WHERE account=$1 AND id NOT IN
			(SELECT id FROM mailbox_push_subscriptions WHERE account=$1 ORDER BY created DESC LIMIT $2)`, account, maxPushDevices)
		return err
	})
	return id, err
}

// DeletePushSubscription forgets one of an account's browsers, by ID or
// by endpoint.
func (e *Engine) DeletePushSubscription(ctx context.Context, account string, id int64, endpoint string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_push_subscriptions WHERE account=$1 AND (id=$2 OR endpoint=$3)`, account, id, endpoint)
	return err
}

// DeletePushSubscriptions forgets every browser an account has, for
// someone recovering a compromised account.
func (e *Engine) DeletePushSubscriptions(ctx context.Context, account string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_push_subscriptions WHERE account=$1`, account)
	return err
}

// SetPushReminders replaces an account's upcoming reminders. It keeps them
// only while one of its browsers wants reminders. A reminder already sent
// stays sent unless its time changed.
func (e *Engine) SetPushReminders(ctx context.Context, account string, in []PushReminder) (int, error) {
	if len(in) > maxPushReminders {
		return 0, &requestError{"too many reminders"}
	}
	var wanted bool
	if err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_push_subscriptions WHERE account=$1 AND reminders)`, account).Scan(&wanted); err != nil {
		return 0, err
	}
	if !wanted {
		_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_push_reminders WHERE account=$1`, account)
		return 0, err
	}
	keys := make([]string, 0, len(in))
	for _, r := range in {
		if r.Key == "" || len(r.Key) > 300 || r.At.IsZero() || r.Starts.IsZero() || !strings.HasPrefix(r.URL, "/") || len(r.URL) > 500 {
			return 0, &requestError{"invalid reminder"}
		}
		keys = append(keys, r.Key)
	}
	err := e.tx(ctx, account, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_push_reminders WHERE account=$1 AND NOT (key = ANY($2))`, account, pq.Array(keys)); err != nil {
			return err
		}
		for _, r := range in {
			if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_push_reminders(account,key,fire_at,starts,title,body,url) VALUES($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (account,key) DO UPDATE SET starts=EXCLUDED.starts,title=EXCLUDED.title,body=EXCLUDED.body,url=EXCLUDED.url,
					fire_at=EXCLUDED.fire_at,
					sent=mailbox_push_reminders.sent AND mailbox_push_reminders.fire_at=EXCLUDED.fire_at`,
				account, r.Key, r.At.UTC(), r.Starts.UTC(), clip(r.Title, 200), clip(r.Body, 300), r.URL); err != nil {
				return err
			}
		}
		return nil
	})
	return len(in), err
}

type dueReminder struct {
	account string
	PushReminder
}

// claimDueReminders marks the reminders that are due as sent and returns
// them. Each goes to one replica: the rows are locked as they are claimed.
func (e *Engine) claimDueReminders(ctx context.Context, now time.Time) ([]dueReminder, error) {
	rows, err := e.DB.QueryContext(ctx, `UPDATE mailbox_push_reminders r SET sent=true
		FROM (SELECT account,key FROM mailbox_push_reminders WHERE NOT sent AND fire_at<=$1 ORDER BY fire_at LIMIT 200 FOR UPDATE SKIP LOCKED) due
		WHERE r.account=due.account AND r.key=due.key
		RETURNING r.account,r.key,r.fire_at,r.starts,r.title,r.body,r.url`, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []dueReminder
	for rows.Next() {
		var d dueReminder
		if err := rows.Scan(&d.account, &d.Key, &d.At, &d.Starts, &d.Title, &d.Body, &d.URL); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- sending ----------------------------------------------------------------

// pusher sends the notifications.
type pusher struct {
	engine *Engine
	log    *slog.Logger
	// sender is filled in on first use, with the stored key pair.
	mu     sync.Mutex
	sender *webpush.Sender
	// client and allowed are the sender's; tests point them at a fake push
	// service. Nil is the real thing.
	client  *http.Client
	allowed func(*url.URL) bool
	pending map[string]*mailBatch
	tested  map[string]time.Time
	ctx     context.Context
	now     func() time.Time
}

type mailItem struct {
	uid      uint32
	from     string
	subject  string
	category string
}

type mailBatch struct {
	account string
	address string
	items   []mailItem
}

func newPusher(ctx context.Context, e *Engine, log *slog.Logger) *pusher {
	return &pusher{engine: e, log: log, pending: map[string]*mailBatch{}, tested: map[string]time.Time{}, ctx: ctx, now: time.Now}
}

// getSender loads the service's VAPID key pair, making it the first time.
func (p *pusher) getSender(ctx context.Context) (*webpush.Sender, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sender != nil {
		return p.sender, nil
	}
	var private string
	err := p.engine.DB.QueryRowContext(ctx, `SELECT private_key FROM mailbox_push_keys WHERE id=1`).Scan(&private)
	if errors.Is(err, sql.ErrNoRows) {
		keys, priv, gerr := webpush.GenerateKeys()
		if gerr != nil {
			return nil, gerr
		}
		// Another replica may get there first; then its key is the one.
		if _, err = p.engine.DB.ExecContext(ctx, `INSERT INTO mailbox_push_keys(id,private_key,public_key) VALUES(1,$1,$2) ON CONFLICT (id) DO NOTHING`, priv, keys.Public); err != nil {
			return nil, err
		}
		err = p.engine.DB.QueryRowContext(ctx, `SELECT private_key FROM mailbox_push_keys WHERE id=1`).Scan(&private)
	}
	if err != nil {
		return nil, err
	}
	keys, err := webpush.ParseKeys(private)
	if err != nil {
		return nil, err
	}
	s := &webpush.Sender{Keys: keys, Client: p.client, Allowed: p.allowed}
	if s.Client == nil {
		s.Client = webpush.DefaultClient()
	}
	p.sender = s
	return s, nil
}

// PublicKey is what browsers subscribe with.
func (p *pusher) PublicKey(ctx context.Context) (string, error) {
	s, err := p.getSender(ctx)
	if err != nil {
		return "", err
	}
	return s.Keys.Public, nil
}

func (p *pusher) checkEndpoint(endpoint string) error {
	s := webpush.Sender{Allowed: p.allowed}
	return s.CheckEndpoint(endpoint)
}

// pushPayload is what the service worker shows (static/sw.js).
type pushPayload struct {
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	Body    string `json:"body,omitempty"`
	Tag     string `json:"tag"`
	URL     string `json:"url"`
	Require bool   `json:"require,omitempty"`
}

func topic(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:32]
}

// send delivers one payload to one browser and keeps the books: a gone
// subscription is forgotten, and one that keeps failing eventually is too.
func (p *pusher) send(ctx context.Context, r pushRow, address string, pl pushPayload, m webpush.Message) error {
	s, err := p.getSender(ctx)
	if err != nil {
		return err
	}
	m.Payload, err = json.Marshal(pl)
	if err != nil {
		return err
	}
	sender := *s
	sender.Contact = r.contact
	if sender.Contact == "" {
		_, domain, _ := strings.Cut(address, "@")
		sender.Contact = "mailto:postmaster@" + domain
	}
	err = sender.Send(ctx, r.sub, m)
	switch {
	case err == nil:
		_, _ = p.engine.DB.ExecContext(ctx, `UPDATE mailbox_push_subscriptions SET last_sent=now(),failures=0 WHERE id=$1`, r.ID)
	case errors.Is(err, webpush.ErrGone):
		_, _ = p.engine.DB.ExecContext(ctx, `DELETE FROM mailbox_push_subscriptions WHERE id=$1`, r.ID)
	default:
		_, _ = p.engine.DB.ExecContext(ctx, `UPDATE mailbox_push_subscriptions SET failures=failures+1 WHERE id=$1`, r.ID)
		_, _ = p.engine.DB.ExecContext(ctx, `DELETE FROM mailbox_push_subscriptions WHERE id=$1 AND failures>=$2`, r.ID, pushGiveUp)
	}
	return err
}

// mailArrived notes a message delivered to an account's inbox. Messages
// that arrive together are announced together, a moment later.
func (p *pusher) mailArrived(a Account, uid uint32, raw []byte, category string) {
	item := mailItem{uid: uid, category: category}
	if h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw))); err == nil {
		mh := gomail.Header{Header: gomessage.Header{Header: h}}
		item.subject, _ = mh.Subject()
		if from, err := mh.AddressList("From"); err == nil && len(from) > 0 {
			item.from = from[0].Name
			if item.from == "" {
				item.from = from[0].Address
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if b, ok := p.pending[a.ID]; ok {
		if len(b.items) < 100 {
			b.items = append(b.items, item)
		}
		return
	}
	p.pending[a.ID] = &mailBatch{account: a.ID, address: a.Address, items: []mailItem{item}}
	time.AfterFunc(pushMailDelay, func() { p.flushMail(a.ID) })
}

func (p *pusher) flushMail(account string) {
	p.mu.Lock()
	b := p.pending[account]
	delete(p.pending, account)
	p.mu.Unlock()
	if b == nil || p.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, time.Minute)
	defer cancel()
	rows, err := p.engine.pushRows(ctx, account)
	if err != nil {
		p.log.Warn("push: read subscriptions", "account", account, "error", err)
		return
	}
	for _, r := range rows {
		items := b.items
		if r.Mail == "off" {
			continue
		}
		if r.Mail == "primary" {
			items = nil
			for _, it := range b.items {
				if it.category == "" {
					items = append(items, it)
				}
			}
		}
		if len(items) == 0 {
			continue
		}
		pl := mailPayload(items, r.Preview)
		if err := p.send(ctx, r, b.address, pl, webpush.Message{TTL: 24 * time.Hour, Urgency: "normal", Topic: "mail"}); err != nil && !errors.Is(err, webpush.ErrGone) {
			p.log.Warn("push: new mail not sent", "account", account, "device", r.ID, "error", err)
		}
	}
}

func mailPayload(items []mailItem, preview bool) pushPayload {
	pl := pushPayload{Kind: "mail", Tag: "elemta-new-mail", URL: "/mail?f=INBOX"}
	switch {
	case !preview:
		pl.Title = "New mail"
		if len(items) > 1 {
			pl.Body = fmt.Sprintf("%d new messages", len(items))
		}
	case len(items) == 1:
		it := items[0]
		pl.Title = clip(it.from, 100)
		if pl.Title == "" {
			pl.Title = "New mail"
		}
		pl.Body = clip(it.subject, 200)
		if pl.Body == "" {
			pl.Body = "(no subject)"
		}
		pl.URL = fmt.Sprintf("/mail?f=INBOX&uid=%d", it.uid)
	default:
		pl.Title = fmt.Sprintf("%d new messages", len(items))
		var lines []string
		for _, it := range items[:min(3, len(items))] {
			lines = append(lines, clip(it.from, 40)+": "+clip(it.subject, 80))
		}
		pl.Body = strings.Join(lines, "\n")
	}
	return pl
}

// sendDueReminders sends the reminders that have come due.
func (p *pusher) sendDueReminders(ctx context.Context) error {
	now := p.now()
	due, err := p.engine.claimDueReminders(ctx, now)
	if err != nil {
		return err
	}
	devices := map[string][]pushRow{}
	addresses := map[string]string{}
	for _, d := range due {
		if d.At.Before(now.Add(-reminderLate)) {
			continue // missed while this service was down; the event's under way
		}
		rows, ok := devices[d.account]
		if !ok {
			if rows, err = p.engine.pushRows(ctx, d.account); err != nil {
				return err
			}
			devices[d.account] = rows
			var address string
			_ = p.engine.DB.QueryRowContext(ctx, `SELECT address FROM mailbox_accounts WHERE id=$1`, d.account).Scan(&address)
			addresses[d.account] = address
		}
		// The event's own start bounds how long the reminder is worth keeping.
		ttl := max(d.Starts.Add(10*time.Minute).Sub(now), time.Minute)
		for _, r := range rows {
			if !r.Reminders {
				continue
			}
			pl := pushPayload{Kind: "reminder", Title: d.Title, Body: d.Body, Tag: d.Key, URL: d.URL, Require: true}
			if !r.Preview {
				pl.Title, pl.Body = "Event reminder", ""
			}
			if err := p.send(ctx, r, addresses[d.account], pl, webpush.Message{TTL: ttl, Urgency: "high", Topic: topic(d.Key)}); err != nil && !errors.Is(err, webpush.ErrGone) {
				p.log.Warn("push: reminder not sent", "account", d.account, "device", r.ID, "error", err)
			}
		}
	}
	// Sent reminders are kept a day, so republishing doesn't send them again.
	_, err = p.engine.DB.ExecContext(ctx, `DELETE FROM mailbox_push_reminders WHERE sent AND starts < $1`, now.Add(-24*time.Hour))
	return err
}

// test sends a notification to one of the account's browsers, at most
// every few seconds.
func (p *pusher) test(ctx context.Context, a Account, endpoint string) error {
	p.mu.Lock()
	if last, ok := p.tested[a.ID]; ok && p.now().Sub(last) < 5*time.Second {
		p.mu.Unlock()
		return errLimited
	}
	p.tested[a.ID] = p.now()
	if len(p.tested) > 10000 {
		p.tested = map[string]time.Time{a.ID: p.now()}
	}
	p.mu.Unlock()
	rows, err := p.engine.pushRows(ctx, a.ID)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Endpoint == endpoint {
			return p.send(ctx, r, a.Address, pushPayload{Kind: "test", Title: "Notifications are on", Body: "This is how new mail and reminders will appear.", Tag: "elemta-test", URL: "/settings/devices"},
				webpush.Message{TTL: 10 * time.Minute, Urgency: "high"})
		}
	}
	return ErrNotFound
}

// run sends reminders as they come due.
func (p *pusher) run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, time.Minute)
			if err := p.sendDueReminders(c); err != nil && c.Err() == nil {
				p.log.Warn("push: reminders", "error", err)
			}
			cancel()
		}
	}
}
