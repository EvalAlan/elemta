package srs

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func rewriter(secrets ...string) *Rewriter {
	r := New(secrets)
	r.now = func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC) }
	return r
}

func TestForwardAndReverse(t *testing.T) {
	r := rewriter("secret")
	got, err := r.Forward("alice@example.org", "forwarder.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "SRS0=") || !strings.HasSuffix(got, "=example.org=alice@forwarder.example") || !Is(got) {
		t.Fatalf("rewritten = %q", got)
	}
	if back, err := r.Reverse(got); err != nil || back != "alice@example.org" {
		t.Fatalf("reverse = %q, %v", back, err)
	}
}

// Some servers change the case of addresses on the way back.
func TestReverseSurvivesCaseChanges(t *testing.T) {
	r := rewriter("secret")
	got, _ := r.Forward("alice@example.org", "forwarder.example")
	for _, changed := range []string{strings.ToLower(got), strings.ToUpper(got)} {
		back, err := r.Reverse(changed)
		if err != nil || !strings.EqualFold(back, "alice@example.org") {
			t.Fatalf("%s: %q, %v", changed, back, err)
		}
	}
}

func TestLocalPartsWithSeparatorsSurvive(t *testing.T) {
	r := rewriter("secret")
	got, err := r.Forward("a=b=c@example.org", "forwarder.example")
	if err != nil {
		t.Fatal(err)
	}
	if back, err := r.Reverse(got); err != nil || back != "a=b=c@example.org" {
		t.Fatalf("reverse = %q, %v", back, err)
	}
}

func TestOwnDomainIsLeftAlone(t *testing.T) {
	got, err := rewriter("secret").Forward("alice@Forwarder.example", "forwarder.example")
	if err != nil || got != "alice@Forwarder.example" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// The hash is what stops this being an open relay.
func TestForgedAddressesAreRefused(t *testing.T) {
	r := rewriter("secret")
	good, _ := r.Forward("alice@example.org", "forwarder.example")
	otherSecret, _ := rewriter("other").Forward("alice@example.org", "forwarder.example")
	retargeted := strings.Replace(good, "=example.org=alice", "=attacker.example=victim", 1)
	for _, address := range []string{otherSecret, retargeted, "SRS0=aaaaaa=aa=example.org=alice@forwarder.example"} {
		if back, err := r.Reverse(address); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %q, %v", address, back, err)
		}
	}
	for _, address := range []string{"alice@example.org", "SRS0=x@forwarder.example", "SRS0=a=b=c=@forwarder.example", "SRS1=x@forwarder.example"} {
		if back, err := r.Reverse(address); err == nil {
			t.Fatalf("%s reversed to %q", address, back)
		}
	}
}

func TestAddressesExpire(t *testing.T) {
	r := rewriter("secret")
	got, _ := r.Forward("alice@example.org", "forwarder.example")
	start := r.now()
	r.now = func() time.Time { return start.Add(MaxAge) }
	if _, err := r.Reverse(got); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	r.now = func() time.Time { return start.Add(MaxAge + day) }
	if _, err := r.Reverse(got); !errors.Is(err, ErrExpired) {
		t.Fatalf("past the limit: %v", err)
	}
}

// The timestamp wraps; an address from just before must still work after.
func TestExpiryAcrossTheTimestampWrap(t *testing.T) {
	r := rewriter("secret")
	wrap := time.Unix(1024*86400*20, 0).UTC()
	r.now = func() time.Time { return wrap.Add(-day) }
	got, _ := r.Forward("alice@example.org", "forwarder.example")
	r.now = func() time.Time { return wrap.Add(day) }
	if _, err := r.Reverse(got); err != nil {
		t.Fatal(err)
	}
}

func TestOldSecretStillVerifies(t *testing.T) {
	got, _ := rewriter("old").Forward("alice@example.org", "forwarder.example")
	if back, err := rewriter("new", "old").Reverse(got); err != nil || back != "alice@example.org" {
		t.Fatalf("reverse = %q, %v", back, err)
	}
	if _, err := rewriter("new").Reverse(got); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a retired secret: %v", err)
	}
}

func TestForwardedTwice(t *testing.T) {
	first, second, third := rewriter("first"), rewriter("second"), rewriter("third")
	once, err := first.Forward("alice@example.org", "one.example")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := second.Forward(once, "two.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(twice, "SRS1=") {
		t.Fatalf("twice = %q", twice)
	}
	thrice, err := third.Forward(twice, "three.example")
	if err != nil {
		t.Fatal(err)
	}
	// Third hop's bounce goes straight to the first forwarder's domain...
	hop, err := third.Reverse(thrice)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(hop, "@one.example") {
		t.Fatalf("third hop reversed to %q", hop)
	}
	// ...which gets the sender back.
	if back, err := first.Reverse(hop); err != nil || back != "alice@example.org" {
		t.Fatalf("first reverse of %q = %q, %v", hop, back, err)
	}
	hop, err = second.Reverse(twice)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := first.Reverse(hop); err != nil || back != "alice@example.org" {
		t.Fatalf("second hop: %q, %v", back, err)
	}
}

func TestTooLongIsRefused(t *testing.T) {
	long := strings.Repeat("a", 60) + "@example.org"
	if got, err := rewriter("secret").Forward(long, "forwarder.example"); !errors.Is(err, ErrTooLong) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNoSecretsMeansOff(t *testing.T) {
	if New(nil) != nil || New([]string{"", " "}) != nil {
		t.Fatal("no secrets should give a nil Rewriter")
	}
	t.Setenv(SecretsEnv, "")
	if FromEnv() != nil {
		t.Fatal("an unset variable should give a nil Rewriter")
	}
	t.Setenv(SecretsEnv, "one, two")
	if r := FromEnv(); r == nil || len(r.secrets) != 2 || string(r.secrets[1]) != "two" {
		t.Fatalf("rewriter = %+v", r)
	}
}
