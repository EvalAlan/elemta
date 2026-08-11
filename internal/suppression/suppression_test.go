package suppression

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Suppression removes people from mailings permanently, so the tests are about
// the two ways that goes wrong: removing someone who should still be mailed,
// and failing to remove someone who should not be.

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "suppression.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSuppressAndCheck(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	if _, suppressed, _ := store.IsSuppressed(ctx, "someone@example.com"); suppressed {
		t.Fatal("nothing should be suppressed to begin with")
	}

	if err := store.Add(ctx, Entry{
		Address: "someone@example.com", Source: SourceBounce,
		Reason: "550 5.1.1 user unknown", Code: "5.1.1",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	entry, suppressed, err := store.IsSuppressed(ctx, "someone@example.com")
	if err != nil || !suppressed {
		t.Fatalf("expected the address to be suppressed (err=%v)", err)
	}
	// The reason has to survive: an operator looking at the list needs to know
	// why an address is on it before deciding to take it off.
	if entry.Source != SourceBounce || !strings.Contains(entry.Reason, "user unknown") {
		t.Errorf("entry = %+v, want the bounce and its reason recorded", entry)
	}
}

// TestSuppressionIsCaseInsensitive: mailing someone who bounced because their
// address arrived capitalised differently is exactly the failure the list
// exists to prevent.
func TestSuppressionIsCaseInsensitive(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	if err := store.Add(ctx, Entry{Address: "Person@Example.COM", Source: SourceBounce}); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"person@example.com", "PERSON@EXAMPLE.COM", " <Person@example.com> "} {
		if _, suppressed, _ := store.IsSuppressed(ctx, variant); !suppressed {
			t.Errorf("%q should be suppressed", variant)
		}
	}
}

// TestFirstReasonWins: a later bounce must not overwrite an earlier complaint.
// A complaint is the more serious fact and the one an operator needs to see.
func TestFirstReasonWins(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	if err := store.Add(ctx, Entry{Address: "a@example.com", Source: SourceComplaint, Reason: "reported as spam"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(ctx, Entry{Address: "a@example.com", Source: SourceBounce, Reason: "user unknown"}); err != nil {
		t.Fatalf("recording an address twice must not be an error: %v", err)
	}

	entry, _, _ := store.IsSuppressed(ctx, "a@example.com")
	if entry.Source != SourceComplaint {
		t.Errorf("source = %q, want the original complaint to survive", entry.Source)
	}
}

func TestListRemoveAndCount(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for _, addr := range []string{"one@example.com", "two@example.net", "three@example.com"} {
		if err := store.Add(ctx, Entry{Address: addr, Source: SourceBounce, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	if n, _ := store.Count(ctx); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}

	entries, total, err := store.List(ctx, "example.com", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(entries) != 2 {
		t.Errorf("filtered list returned %d of %d, want 2 of 2", len(entries), total)
	}

	removed, err := store.Remove(ctx, "ONE@EXAMPLE.COM")
	if err != nil || !removed {
		t.Errorf("removal should work and be case-insensitive (removed=%v err=%v)", removed, err)
	}
	if _, suppressed, _ := store.IsSuppressed(ctx, "one@example.com"); suppressed {
		t.Error("the address should no longer be suppressed")
	}
}

// TestClassificationSuppressesOnlyTheRecipientsFault is the heart of it.
//
// A 5xx can be about the recipient, about the message, or about us. Only the
// first means the address should never be mailed again; treating the others the
// same way deletes valid addresses from a list because our IP was blocked or
// our message was too big, and nobody notices they stopped receiving mail.
func TestClassificationSuppressesOnlyTheRecipientsFault(t *testing.T) {
	suppress := []struct{ code, text string }{
		{"5.1.1", "550 5.1.1 <a@example.com>: user unknown"},
		{"5.1.1", "550 no such user here"},
		{"", "550 recipient not found"},
		{"5.1.6", "550 mailbox has moved"},
		{"", "550 invalid recipient"},
	}
	for _, tc := range suppress {
		if _, ok := ShouldSuppress(tc.code, tc.text); !ok {
			t.Errorf("should suppress: %q %q", tc.code, tc.text)
		}
	}

	keep := []struct{ code, text string }{
		{"5.2.2", "552 mailbox full"},                         // the person exists
		{"5.2.3", "552 message too large"},                    // our message, not their address
		{"5.7.1", "550 blocked by policy"},                    // about us
		{"5.7.1", "550 your IP is on a blocklist"},            // about us
		{"5.7.1", "550 message rejected as spam"},             // about our content
		{"4.7.1", "451 greylisted, try again later"},          // not permanent at all
		{"5.5.0", "550 something this code has not heard of"}, // unrecognised: do not guess
	}
	for _, tc := range keep {
		if source, ok := ShouldSuppress(tc.code, tc.text); ok {
			t.Errorf("should NOT suppress (%s): %q %q", source, tc.code, tc.text)
		}
	}
}

// TestComplaintsOutrankEverything: the address works and the person has said
// they do not want the mail, which is worse than a bounce, not better.
func TestComplaintsOutrankEverything(t *testing.T) {
	source, ok := ShouldSuppress("", "abuse report received for this recipient")
	if !ok || source != SourceComplaint {
		t.Errorf("got (%q, %v), want a complaint", source, ok)
	}
}

// TestMissingStoreIsNotAnError: a nil store must behave as "nothing is
// suppressed" rather than panicking or refusing to send, so that a deployment
// without one still delivers mail.
func TestMissingStoreIsNotAnError(t *testing.T) {
	var store *Store
	ctx := context.Background()

	if _, suppressed, err := store.IsSuppressed(ctx, "a@example.com"); suppressed || err != nil {
		t.Errorf("nil store: suppressed=%v err=%v, want false and no error", suppressed, err)
	}
	if err := store.Add(ctx, Entry{Address: "a@example.com"}); err != nil {
		t.Errorf("nil store Add should be a no-op, got %v", err)
	}
}
