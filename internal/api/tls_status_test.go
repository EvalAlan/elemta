package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Certificate expiry is predictable — the date is written on the certificate —
// so the only way it causes an outage is if nothing looks at it. These tests
// are about looking at it correctly, particularly around the boundaries.

func writeTestCert(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.test.example"},
		DNSNames:     []string{"mail.test.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	return path
}

func statusFor(t *testing.T, path string) TLSCertificateStatus {
	t.Helper()
	s := &Server{mainConfig: &MainConfig{TLSEnabled: true, TLSCertFile: path}}
	return s.tlsCertificateStatus()
}

func TestCertificateStatusThresholds(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		expires  time.Duration
		want     string
		wantDays int
	}{
		{"comfortably valid", 90 * 24 * time.Hour, "ok", 89},
		{"just inside the warning window", 13 * 24 * time.Hour, "warning", 12},
		{"critical", 2 * 24 * time.Hour, "critical", 1},
		{"expired", -24 * time.Hour, "expired", -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := statusFor(t, writeTestCert(t, now.Add(-time.Hour), now.Add(tc.expires)))
			if status.Status != tc.want {
				t.Errorf("status = %q, want %q (message: %s)", status.Status, tc.want, status.Message)
			}
			// Days are rounded down, so a certificate never reports the safe
			// side of a threshold it has already crossed.
			if status.DaysRemaining != tc.wantDays {
				t.Errorf("days remaining = %d, want %d", status.DaysRemaining, tc.wantDays)
			}
			if status.Message == "" {
				t.Error("every status needs a line an operator can read")
			}
		})
	}
}

func TestCertificateStatusExpiredIsUnambiguous(t *testing.T) {
	status := statusFor(t, writeTestCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)))
	if !status.Expired {
		t.Error("an expired certificate must be reported as expired")
	}
	if !strings.Contains(strings.ToLower(status.Message), "expired") {
		t.Errorf("message should say so plainly: %q", status.Message)
	}
}

// TestCertificateNotYetValid: a certificate from the future fails handshakes
// exactly as thoroughly as an expired one, and a wrong clock produces it.
func TestCertificateNotYetValid(t *testing.T) {
	status := statusFor(t, writeTestCert(t, time.Now().Add(48*time.Hour), time.Now().Add(90*24*time.Hour)))
	if status.Status != "critical" {
		t.Errorf("status = %q, want critical for a certificate that is not valid yet", status.Status)
	}
	if !strings.Contains(status.Message, "Not valid until") {
		t.Errorf("message should explain why: %q", status.Message)
	}
}

func TestCertificateStatusReportsSelfSigned(t *testing.T) {
	status := statusFor(t, writeTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	if !status.SelfSigned {
		t.Error("a certificate that issued itself is self-signed")
	}
	if !strings.Contains(status.Message, "not trust") {
		t.Errorf("a self-signed certificate should say what that means: %q", status.Message)
	}
}

// TestNoCertificateConfiguredIsNotAWarning: a server accepting only plaintext
// on a private network has nothing to report, and inventing a warning for it
// trains operators to ignore the panel.
func TestNoCertificateConfiguredIsNotAWarning(t *testing.T) {
	s := &Server{mainConfig: &MainConfig{}}
	status := s.tlsCertificateStatus()
	if status.Configured {
		t.Error("nothing is configured")
	}
	if status.Status == "warning" || status.Status == "critical" {
		t.Errorf("status = %q; an unconfigured certificate is not a problem", status.Status)
	}
}

// TestUnreadableCertificateIsCritical: TLS switched on with a certificate that
// cannot be read is a server that fails every handshake, which is not a quiet
// condition.
func TestUnreadableCertificateIsCritical(t *testing.T) {
	status := statusFor(t, filepath.Join(t.TempDir(), "does-not-exist.crt"))
	if status.Status != "critical" {
		t.Errorf("status = %q, want critical", status.Status)
	}

	// A file that exists but holds no certificate is the same problem.
	junk := filepath.Join(t.TempDir(), "junk.crt")
	if err := os.WriteFile(junk, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := statusFor(t, junk); status.Status != "critical" {
		t.Errorf("status = %q for a file with no certificate, want critical", status.Status)
	}
}

// TestReadsTheLeafFromABundle: a chain file has the leaf first, and it is the
// leaf's dates that matter — an intermediate outliving it tells you nothing.
func TestReadsTheLeafFromABundle(t *testing.T) {
	leafPath := writeTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))
	leaf, err := os.ReadFile(leafPath) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	intermediatePath := writeTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(3650*24*time.Hour))
	intermediate, err := os.ReadFile(intermediatePath) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(t.TempDir(), "bundle.crt")
	if err := os.WriteFile(bundle, append(leaf, intermediate...), 0o600); err != nil {
		t.Fatal(err)
	}

	status := statusFor(t, bundle)
	if status.Status != "warning" {
		t.Errorf("status = %q, want the leaf's warning rather than the intermediate's decade", status.Status)
	}
}
