package queue

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/dane"
	"github.com/EvalAlan/elemta/internal/tlsrpt"
)

// fakeDANE answers DANE lookups from fixed data.
type fakeDANE struct {
	mxSecure bool
	mxErr    error
	tlsa     []dane.TLSA
	tlsaErr  error
	lookups  int
}

func (f *fakeDANE) MXSecure(context.Context, string) (bool, error) { return f.mxSecure, f.mxErr }
func (f *fakeDANE) LookupTLSA(context.Context, string, int) ([]dane.TLSA, bool, error) {
	f.lookups++
	return f.tlsa, f.tlsaErr == nil, f.tlsaErr
}

func spkiRecord(t *testing.T, cert tls.Certificate) dane.TLSA {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return dane.TLSA{Usage: dane.UsageDANEEE, Selector: dane.SelectorSPKI, MatchingType: dane.MatchSHA256, Data: sum[:]}
}

func daneSetup(t *testing.T, offerTLS bool) (*reuseServer, *SMTPDeliveryHandler, *tlsRecorder, tls.Certificate) {
	t.Helper()
	cert := generateSelfSignedCert(t)
	srv := startReuseServer(t, 0)
	if offerTLS {
		srv.cert = &cert
	}
	h := reuseHandler(srv)
	t.Cleanup(h.CloseIdleSessions)
	rec := &tlsRecorder{}
	h.SetTLSReportRecorder(rec)
	return srv, h, rec, cert
}

func deliver(h *SMTPDeliveryHandler, to string) (*DeliveryResult, error) {
	return h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "sender@example.com", To: []string{to}}, []byte("Subject: x\r\n\r\nbody\r\n"))
}

// A self-signed certificate that fails web PKI validation is authenticated
// by its TLSA record.
func TestDANEAuthenticatesMatchingCertificate(t *testing.T) {
	srv, h, rec, cert := daneSetup(t, true)
	h.SetDANEResolver(&fakeDANE{mxSecure: true, tlsa: []dane.TLSA{spkiRecord(t, cert)}})

	deliverOne(t, h, "a@one.test")
	if srv.messages.Load() != 1 {
		t.Fatal("not delivered")
	}
	if len(rec.sessions) != 1 || !rec.sessions[0].Success || rec.sessions[0].Policy.Type != tlsrpt.PolicyTypeTLSA {
		t.Errorf("TLS report = %+v", rec.sessions)
	}
}

// A certificate that matches no TLSA record is refused outright. The
// opportunistic fallbacks (unverified TLS, plaintext) are exactly the
// downgrade DANE prevents, so none is tried.
func TestDANERefusesMismatchWithoutFallback(t *testing.T) {
	srv, h, rec, _ := daneSetup(t, true)
	other := generateSelfSignedCert(t)
	h.SetDANEResolver(&fakeDANE{mxSecure: true, tlsa: []dane.TLSA{spkiRecord(t, other)}})

	_, err := deliver(h, "a@one.test")
	if err == nil {
		t.Fatal("delivered despite TLSA mismatch")
	}
	if srv.messages.Load() != 0 {
		t.Error("message sent over an unauthenticated session")
	}
	if got := srv.conns.Load(); got != 1 {
		t.Errorf("connections = %d, want 1 (no fallback reconnects)", got)
	}
	var perm interface{ Permanent() bool }
	if errors.As(err, &perm) && perm.Permanent() {
		t.Error("DANE failure treated as permanent; it should defer")
	}
	if len(rec.sessions) != 1 || rec.sessions[0].ResultType != tlsrpt.ResultTLSAInvalid {
		t.Errorf("TLS report = %+v", rec.sessions)
	}
}

func TestDANERequiresSTARTTLS(t *testing.T) {
	srv, h, rec, cert := daneSetup(t, false)
	h.SetDANEResolver(&fakeDANE{mxSecure: true, tlsa: []dane.TLSA{spkiRecord(t, cert)}})

	if _, err := deliver(h, "a@one.test"); err == nil {
		t.Fatal("delivered in plaintext to a host with TLSA records")
	}
	if srv.messages.Load() != 0 {
		t.Error("message sent in plaintext")
	}
	if len(rec.sessions) != 1 || rec.sessions[0].ResultType != tlsrpt.ResultDANERequired {
		t.Errorf("TLS report = %+v", rec.sessions)
	}
}

// Unsigned MX records mean DANE does not apply, whatever TLSA says: the MX
// host itself could have been substituted.
func TestDANEIgnoredWhenMXUnsigned(t *testing.T) {
	_, h, _, _ := daneSetup(t, false)
	f := &fakeDANE{mxSecure: false, tlsa: []dane.TLSA{{Usage: 3, Selector: 1, MatchingType: 1, Data: make([]byte, 32)}}}
	h.SetDANEResolver(f)

	deliverOne(t, h, "a@one.test")
	if f.lookups != 0 {
		t.Error("TLSA looked up for a domain with unsigned MX records")
	}
}

// A failed DNSSEC lookup defers rather than delivering without DANE.
func TestDANELookupFailureDefers(t *testing.T) {
	srv, h, rec, _ := daneSetup(t, true)
	h.SetDANEResolver(&fakeDANE{mxSecure: true, tlsaErr: dane.ErrBogus})

	_, err := deliver(h, "a@one.test")
	if err == nil || !strings.Contains(err.Error(), "DANE lookup") {
		t.Fatalf("err = %v, want a DANE lookup deferral", err)
	}
	if srv.conns.Load() != 0 {
		t.Error("connected despite failed TLSA lookup")
	}
	if len(rec.sessions) != 1 || rec.sessions[0].ResultType != tlsrpt.ResultDNSSECInvalid {
		t.Errorf("TLS report = %+v", rec.sessions)
	}
}

// A parked session set up without DANE (for a domain whose MX records are
// unsigned) is not reused for a message where DANE applies.
func TestDANEDoesNotReuseUnauthenticatedSession(t *testing.T) {
	srv, h, _, cert := daneSetup(t, true)
	f := &fakeDANE{mxSecure: false, tlsa: []dane.TLSA{spkiRecord(t, cert)}}
	h.SetDANEResolver(f)
	deliverOne(t, h, "a@unsigned.test")
	// The self-signed certificate fails web PKI validation, so this session
	// came from the opportunistic fallback and may have taken two connections.
	before := srv.conns.Load()

	f.mxSecure = true
	deliverOne(t, h, "b@signed.test")
	if got := srv.conns.Load() - before; got != 1 {
		t.Errorf("new connections = %d, want 1 (no reuse of the non-DANE session)", got)
	}

	// And the DANE session is reusable for the next DANE message.
	deliverOne(t, h, "c@signed.test")
	if got := srv.conns.Load() - before; got != 1 {
		t.Errorf("connections = %d, want DANE session reused", got)
	}
}
