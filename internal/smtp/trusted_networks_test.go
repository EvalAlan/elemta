package smtp

import (
	"strings"
	"testing"
)

// Peer classification decides whether a connection gets the permissive
// content-validation path, so getting it wrong either refuses legitimate mail
// or skips security checks for someone who should not have them skipped.
//
// It used to be decided by string prefixes on the address text, which is wrong
// in two ways that matter, and which also made the external path unreachable
// from any test — every test connects over loopback, and the compose stack
// connects from a Docker address. That blind spot is why three separate bugs
// in the external path survived: nothing had ever executed it.

func handlerWithPeer(t *testing.T, peer string, trusted []string) *DataHandler {
	t.Helper()
	return &DataHandler{
		logger:            quietLogger(),
		conn:              &fakeConn{remote: &mockAddr{addr: peer}},
		config:            &Config{Hostname: "mail.example.com", TrustedNetworks: trusted},
		enhancedValidator: NewEnhancedValidator(quietLogger()),
	}
}

// TestPeerClassification covers the ranges themselves, including the two the
// old prefix matching got wrong.
func TestPeerClassification(t *testing.T) {
	cases := []struct {
		name       string
		peer       string
		wantIntern bool
	}{
		{"IPv4 loopback", "127.0.0.1:2525", true},
		{"IPv6 loopback", "[::1]:2525", true},
		{"RFC1918 10/8", "10.1.2.3:2525", true},
		// 192.168/16 is private but is not trusted by default: the previous
		// implementation never granted it, and this change deliberately does
		// not widen trust. Operators can add it via trusted_networks.
		{"RFC1918 192.168/16 not trusted by default", "192.168.1.10:2525", false},
		{"Docker 172.17", "172.17.0.5:2525", true},
		{"RFC1918 172.16 lower bound", "172.16.0.1:2525", true},
		{"RFC1918 172.31 upper bound", "172.31.255.254:2525", true},

		// The prefix test matched "172." — that is 172.0.0.0/8, but only
		// 172.16.0.0/12 is private. Everything below and above the /12 is
		// public and was being handed the permissive path.
		{"public 172.15 below the private block", "172.15.0.1:2525", false},
		{"public 172.32 above the private block", "172.32.5.5:2525", false},
		{"public 172.217 (google)", "172.217.16.14:2525", false},

		// The loopback test used strings.Contains(addr, "::1"), which matches
		// any IPv6 address ending in ::1 — the conventional first host address
		// in a subnet, and routable.
		{"public IPv6 ending in ::1", "[2001:db8::1]:2525", false},
		{"public IPv6 ending in ::1 with subnet", "[2600:1f18:1234::1]:2525", false},

		{"ordinary public IPv4", "203.0.113.5:2525", false},
		{"ordinary public IPv6", "[2001:db8::dead:beef]:2525", false},
		{"unparseable address", "not-an-address", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dh := handlerWithPeer(t, tc.peer, nil) // nil = built-in defaults
			if got := dh.isInternalConnection(); got != tc.wantIntern {
				t.Errorf("peer %s: internal = %v, want %v", tc.peer, got, tc.wantIntern)
			}
		})
	}
}

// TestTrustedNetworksOverride is the seam that closes the blind spot: a test
// running over loopback can declare loopback untrusted and so drive the code
// path that real inbound mail from the internet takes.
func TestTrustedNetworksOverride(t *testing.T) {
	t.Run("empty list trusts nothing", func(t *testing.T) {
		dh := handlerWithPeer(t, "127.0.0.1:2525", []string{})
		if dh.isInternalConnection() {
			t.Error("loopback should be external when trusted_networks is explicitly empty")
		}
	})

	t.Run("nil list uses the defaults", func(t *testing.T) {
		dh := handlerWithPeer(t, "127.0.0.1:2525", nil)
		if !dh.isInternalConnection() {
			t.Error("loopback should be internal under the default trusted networks")
		}
	})

	t.Run("192.168 can be opted into", func(t *testing.T) {
		dh := handlerWithPeer(t, "192.168.1.10:2525", []string{"192.168.0.0/16"})
		if !dh.isInternalConnection() {
			t.Error("a configured 192.168 network should be trusted")
		}
	})

	t.Run("custom list is honoured", func(t *testing.T) {
		dh := handlerWithPeer(t, "203.0.113.5:2525", []string{"203.0.113.0/24"})
		if !dh.isInternalConnection() {
			t.Error("a peer inside a configured trusted network should be internal")
		}

		other := handlerWithPeer(t, "198.51.100.7:2525", []string{"203.0.113.0/24"})
		if other.isInternalConnection() {
			t.Error("a peer outside the configured trusted networks should be external")
		}
	})

	t.Run("configuring a list replaces the defaults", func(t *testing.T) {
		dh := handlerWithPeer(t, "127.0.0.1:2525", []string{"203.0.113.0/24"})
		if dh.isInternalConnection() {
			t.Error("loopback should not remain trusted once an explicit list is configured")
		}
	})
}

// TestExternalPathReachableOverLoopback is the point of the whole change: an
// ordinary server test, connecting the only way a test can, exercising the
// branch that only external senders reach.
func TestExternalPathReachableOverLoopback(t *testing.T) {
	cfg := strictTestConfig(t)
	cfg.TrustedNetworks = []string{} // treat this loopback connection as external

	queueDir := cfg.QueueDir
	conn, reader := dialGreeted(t, cfg)

	// A body well over the per-line limit: the shape that was rejected for
	// every external sender until it was fixed.
	body := strings.Repeat("An ordinary line of message text for the body.\r\n", 60)
	resp := submitMessage(t, conn, reader, "Subject: external\r\n\r\n"+body+".\r\n")

	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("ordinary mail on the external path was rejected: %s", resp)
	}

	stored := string(waitForStoredMessage(t, queueDir))
	if !strings.HasSuffix(stored, body) {
		t.Error("body was not stored verbatim on the external path")
	}
}

// TestExternalPathStillRejectsBadInput confirms the override exercises the
// external branch rather than disabling validation: a bare LF must still be
// refused there.
func TestExternalPathStillRejectsBadInput(t *testing.T) {
	cfg := strictTestConfig(t)
	cfg.TrustedNetworks = []string{}

	conn, reader := dialGreeted(t, cfg)
	resp := submitMessage(t, conn, reader, "Subject: bad\r\n\r\nline one\nline two\r\n.\r\n")

	if strings.HasPrefix(resp, "250") {
		t.Errorf("bare LF should still be rejected on the external path, got %s", resp)
	}
}

// TestValidateTrustedNetworks pins the startup check.
func TestValidateTrustedNetworks(t *testing.T) {
	if err := (&Config{TrustedNetworks: []string{"10.0.0.0/8", "203.0.113.0/24"}}).ValidateTrustedNetworks(); err != nil {
		t.Errorf("valid CIDRs were rejected: %v", err)
	}
	if err := (&Config{TrustedNetworks: nil}).ValidateTrustedNetworks(); err != nil {
		t.Errorf("an unset list should be valid: %v", err)
	}
	if err := (&Config{TrustedNetworks: []string{}}).ValidateTrustedNetworks(); err != nil {
		t.Errorf("an empty list should be valid: %v", err)
	}
	if err := (&Config{TrustedNetworks: []string{"10.0.0.0/8", "not-a-cidr"}}).ValidateTrustedNetworks(); err == nil {
		t.Error("a malformed CIDR should be rejected rather than silently dropped")
	}
}

// TestNewServerRejectsMalformedTrustedNetworks makes sure the check is wired
// into startup, not just available.
func TestNewServerRejectsMalformedTrustedNetworks(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.TrustedNetworks = []string{"192.168.0.0/16", "garbage"}

	if _, err := NewServer(cfg); err == nil {
		t.Error("NewServer should refuse to start with a malformed trusted_networks entry")
	}
}

// TestIsInternalConnectionIsCached guards the per-line cost: this is consulted
// for every line of DATA, so it must not reparse the address each time.
func TestIsInternalConnectionIsCached(t *testing.T) {
	dh := handlerWithPeer(t, "127.0.0.1:2525", nil)

	if !dh.isInternalConnection() {
		t.Fatal("expected loopback to be internal")
	}
	if !dh.internalPeerKnown {
		t.Error("classification should be cached after the first call")
	}

	// Swapping the address underneath must not change the answer: the peer
	// cannot change within a session, and the cached value is what is used.
	dh.conn = &fakeConn{remote: &mockAddr{addr: "203.0.113.5:2525"}}
	if !dh.isInternalConnection() {
		t.Error("cached classification should be reused rather than recomputed")
	}
}

func TestParseTrustedNetworks(t *testing.T) {
	if nets, err := ParseTrustedNetworks(nil); err != nil || len(nets) == 0 {
		t.Errorf("nil should yield the defaults, got %d networks, err %v", len(nets), err)
	}
	if nets, err := ParseTrustedNetworks([]string{}); err != nil || len(nets) != 0 {
		t.Errorf("an empty list should yield no networks, got %d, err %v", len(nets), err)
	}
	if _, err := ParseTrustedNetworks([]string{" 10.0.0.0/8 "}); err != nil {
		t.Errorf("surrounding whitespace should be tolerated: %v", err)
	}
	if _, err := ParseTrustedNetworks([]string{"10.0.0.1"}); err == nil {
		t.Error("a bare IP without a prefix length should be rejected")
	}
}
