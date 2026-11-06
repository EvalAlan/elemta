package mailbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/EvalAlan/elemta/internal/webpush"
)

// fakePushService plays a browser's push service and the browser behind it:
// it decrypts what arrives with the browser's key.
type fakePushService struct {
	t    *testing.T
	srv  *httptest.Server
	key  *ecdh.PrivateKey
	auth []byte
	got  chan pushPayload
	mu   sync.Mutex
	code int
}

func newFakePushService(t *testing.T) *fakePushService {
	f := &fakePushService{t: t, got: make(chan pushPayload, 16), code: http.StatusCreated, auth: make([]byte, 16)}
	f.key, _ = ecdh.P256().GenerateKey(rand.Reader)
	_, _ = rand.Read(f.auth)
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		code := f.code
		f.mu.Unlock()
		w.WriteHeader(code)
		if code >= 300 {
			return
		}
		plain, err := webpush.Decrypt(f.key, f.auth, body)
		if err != nil {
			t.Errorf("push didn't decrypt: %v", err)
			return
		}
		var p pushPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			t.Errorf("payload: %v", err)
		}
		f.got <- p
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePushService) subscribe(endpoint string) PushSubscribe {
	return PushSubscribe{
		Endpoint: f.srv.URL + endpoint, P256dh: base64.RawURLEncoding.EncodeToString(f.key.PublicKey().Bytes()),
		Auth: base64.RawURLEncoding.EncodeToString(f.auth), Label: "Firefox on Linux", Mail: "all", Reminders: true, Preview: true,
		Contact: "https://mail.example.com/settings",
	}
}

func (f *fakePushService) next(t *testing.T) pushPayload {
	t.Helper()
	select {
	case p := <-f.got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no push arrived")
	}
	return pushPayload{}
}

func (f *fakePushService) none(t *testing.T) {
	t.Helper()
	select {
	case p := <-f.got:
		t.Fatalf("unexpected push %+v", p)
	case <-time.After(300 * time.Millisecond):
	}
}

func pushTestService(t *testing.T) (*Service, Account, *fakePushService) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	f := newFakePushService(t)
	s.push.client = f.srv.Client()
	s.push.allowed = func(u *url.URL) bool { return strings.HasPrefix(u.String(), f.srv.URL) }
	old := pushMailDelay
	pushMailDelay = 50 * time.Millisecond
	t.Cleanup(func() { pushMailDelay = old })
	return s, a, f
}

func TestPushSubscriptions(t *testing.T) {
	s, a, f := pushTestService(t)
	ctx := context.Background()
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, PushSubscribe{Endpoint: "https://attacker.example/x", P256dh: f.subscribe("").P256dh, Auth: f.subscribe("").Auth, Mail: "all"}, s.push.checkEndpoint); err == nil {
		t.Fatal("an endpoint off the push services was accepted")
	}
	bad := f.subscribe("/1")
	bad.Auth = "short"
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, bad, s.push.checkEndpoint); err == nil {
		t.Fatal("a bad auth secret was accepted")
	}
	id, err := s.engine.PutPushSubscription(ctx, a.ID, f.subscribe("/1"), s.push.checkEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	// Changing what the device wants keeps it one device.
	in := f.subscribe("/1")
	in.Mail, in.Reminders = "primary", false
	if again, err := s.engine.PutPushSubscription(ctx, a.ID, in, s.push.checkEndpoint); err != nil || again != id {
		t.Fatalf("update: %d %v, want %d", again, err, id)
	}
	devices, err := s.engine.PushDevices(ctx, a.ID)
	if err != nil || len(devices) != 1 || devices[0].Mail != "primary" || devices[0].Reminders || devices[0].Label != "Firefox on Linux" {
		t.Fatalf("devices = %+v, %v", devices, err)
	}
	// The same browser signed in as someone else moves to them.
	other := Account{ID: uuid.NewString(), Address: uuid.NewString() + "@example.com"}
	if err := s.engine.EnsureAccount(ctx, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.engine.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, other.ID) })
	if _, err := s.engine.PutPushSubscription(ctx, other.ID, f.subscribe("/1"), s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	if devices, _ := s.engine.PushDevices(ctx, a.ID); len(devices) != 0 {
		t.Fatalf("the device stayed with the first account: %+v", devices)
	}
	// At most maxPushDevices, the oldest dropped.
	for i := range maxPushDevices + 3 {
		if _, err := s.engine.PutPushSubscription(ctx, a.ID, f.subscribe("/many/"+string(rune('a'+i))), s.push.checkEndpoint); err != nil {
			t.Fatal(err)
		}
	}
	if devices, _ := s.engine.PushDevices(ctx, a.ID); len(devices) != maxPushDevices {
		t.Fatalf("%d devices, want %d", len(devices), maxPushDevices)
	}
	if err := s.engine.DeletePushSubscriptions(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if devices, _ := s.engine.PushDevices(ctx, a.ID); len(devices) != 0 {
		t.Fatalf("%d devices left", len(devices))
	}
}

func TestPushNewMail(t *testing.T) {
	s, a, f := pushTestService(t)
	ctx := context.Background()
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, f.subscribe("/mail"), s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	deliver := func(subject string) {
		t.Helper()
		raw := []byte("From: Priya Raman <priya@northwind.example>\r\nTo: " + a.Address + "\r\nSubject: " + subject + "\r\nMessage-ID: <" + uuid.NewString() + "@northwind.example>\r\n\r\nHello\r\n")
		if err := s.deliver(ctx, delivery{account: a, from: "priya@northwind.example", rcpt: a.Address, raw: raw}); err != nil {
			t.Fatal(err)
		}
	}
	deliver("Kickoff")
	p := f.next(t)
	if p.Kind != "mail" || p.Title != "Priya Raman" || p.Body != "Kickoff" || !strings.HasPrefix(p.URL, "/mail?f=INBOX&uid=") || p.Tag != "elemta-new-mail" {
		t.Fatalf("payload = %+v", p)
	}
	// Two together are one notification.
	deliver("One")
	deliver("Two")
	if p := f.next(t); p.Title != "2 new messages" || !strings.Contains(p.Body, "Priya Raman: One") {
		t.Fatalf("payload = %+v", p)
	}
	f.none(t)

	// Primary only: a promotion stays quiet.
	in := f.subscribe("/mail")
	in.Mail = "primary"
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, in, s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	// (Delivery works the tab out itself; this is what it hands on.)
	s.push.mailArrived(a, 99, []byte("From: Shop <deals@shop.example>\r\nSubject: Sale\r\n\r\n"), "$CategoryPromotions")
	f.none(t)
	s.push.mailArrived(a, 100, []byte("From: Shop <deals@shop.example>\r\nSubject: Receipt\r\n\r\n"), "")
	if p := f.next(t); p.Body != "Receipt" || p.URL != "/mail?f=INBOX&uid=100" {
		t.Fatalf("payload = %+v", p)
	}

	// No preview: the lock screen says only that there's mail.
	in.Mail, in.Preview = "all", false
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, in, s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	deliver("Secret plans")
	if p := f.next(t); p.Title != "New mail" || strings.Contains(p.Body+p.Title, "Secret") || strings.Contains(p.Body+p.Title, "Priya") {
		t.Fatalf("payload = %+v", p)
	}

	// A browser that unsubscribed is forgotten the next time.
	f.mu.Lock()
	f.code = http.StatusGone
	f.mu.Unlock()
	deliver("Anyone there?")
	deadline := time.Now().Add(5 * time.Second)
	for {
		devices, _ := s.engine.PushDevices(ctx, a.ID)
		if len(devices) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a gone subscription was kept")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPushReminders(t *testing.T) {
	s, a, f := pushTestService(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	rem := []PushReminder{
		{Key: "standup@1", At: now.Add(-time.Minute), Starts: now.Add(9 * time.Minute), Title: "Standup", Body: "10:00 · Room 4", URL: "/calendar/event?uid=standup"},
		{Key: "later@1", At: now.Add(time.Hour), Starts: now.Add(2 * time.Hour), Title: "Later", URL: "/calendar"},
		{Key: "missed@1", At: now.Add(-time.Hour), Starts: now.Add(-50 * time.Minute), Title: "Missed", URL: "/calendar"},
	}
	// Nobody wants reminders yet: nothing is kept.
	if n, err := s.engine.SetPushReminders(ctx, a.ID, rem); err != nil || n != 0 {
		t.Fatalf("stored %d, %v", n, err)
	}
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, f.subscribe("/rem"), s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	if n, err := s.engine.SetPushReminders(ctx, a.ID, rem); err != nil || n != 3 {
		t.Fatalf("stored %d, %v", n, err)
	}
	if err := s.push.sendDueReminders(ctx); err != nil {
		t.Fatal(err)
	}
	p := f.next(t)
	if p.Kind != "reminder" || p.Title != "Standup" || p.Body != "10:00 · Room 4" || p.Tag != "standup@1" || !p.Require {
		t.Fatalf("payload = %+v", p)
	}
	f.none(t) // not the later one, and not the one long past

	// Publishing again doesn't send it twice; moving it does.
	if _, err := s.engine.SetPushReminders(ctx, a.ID, rem); err != nil {
		t.Fatal(err)
	}
	if err := s.push.sendDueReminders(ctx); err != nil {
		t.Fatal(err)
	}
	f.none(t)
	rem[0].At = now.Add(-30 * time.Second)
	if _, err := s.engine.SetPushReminders(ctx, a.ID, rem[:2]); err != nil {
		t.Fatal(err)
	}
	if err := s.push.sendDueReminders(ctx); err != nil {
		t.Fatal(err)
	}
	if p := f.next(t); p.Tag != "standup@1" {
		t.Fatalf("payload = %+v", p)
	}
	// Turning reminders off on the last device drops what was stored.
	in := f.subscribe("/rem")
	in.Reminders = false
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, in, s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.engine.SetPushReminders(ctx, a.ID, rem); n != 0 {
		t.Fatalf("stored %d with reminders off", n)
	}
	var left int
	_ = s.engine.DB.QueryRow(`SELECT count(*) FROM mailbox_push_reminders WHERE account=$1`, a.ID).Scan(&left)
	if left != 0 {
		t.Fatalf("%d reminders kept", left)
	}
}

func TestPushTest(t *testing.T) {
	s, a, f := pushTestService(t)
	ctx := context.Background()
	in := f.subscribe("/test")
	if _, err := s.engine.PutPushSubscription(ctx, a.ID, in, s.push.checkEndpoint); err != nil {
		t.Fatal(err)
	}
	if err := s.push.test(ctx, a, in.Endpoint); err != nil {
		t.Fatal(err)
	}
	if p := f.next(t); p.Kind != "test" {
		t.Fatalf("payload = %+v", p)
	}
	if err := s.push.test(ctx, a, in.Endpoint); err == nil {
		t.Fatal("a second test at once wasn't limited")
	}
	key, err := s.push.PublicKey(ctx)
	if err != nil || len(key) != 87 {
		t.Fatalf("public key %q, %v", key, err)
	}
}
