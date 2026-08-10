package api

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// TLS certificate status.
//
// An expired certificate is one of the most common ways a mail server stops
// working, and it is entirely predictable: the date is written on the
// certificate. The only reason it takes anyone by surprise is that nothing was
// looking at it.
//
// This reads the configured certificate and says when it runs out. It does not
// renew anything — reporting is the part that was missing.

const (
	// certWarnDays is when a certificate starts being a problem worth acting on.
	// Two weeks is enough to notice, raise a ticket and renew by hand if the
	// automation has failed; shorter and the warning arrives at the same time as
	// the outage.
	certWarnDays = 14
	// certCriticalDays is when it becomes urgent.
	certCriticalDays = 3
)

// TLSCertificateStatus is what the dashboard shows about the certificate.
type TLSCertificateStatus struct {
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
	Path       string `json:"path,omitempty"`

	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	DNSNames  []string `json:"dns_names,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`

	DaysRemaining int  `json:"days_remaining"`
	Expired       bool `json:"expired"`
	// SelfSigned is worth saying out loud: it is fine for a development stack
	// and means no sending server will trust this one in production.
	SelfSigned bool `json:"self_signed"`

	// Status is ok, warning, critical, expired or unknown, so the UI does not
	// have to re-derive the thresholds and disagree with the API about them.
	Status string `json:"status"`
	// Message is the one line an operator needs to read.
	Message string `json:"message"`
}

// handleTLSCertificate reports on the configured certificate.
func (s *Server) handleTLSCertificate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.tlsCertificateStatus())
}

func (s *Server) tlsCertificateStatus() TLSCertificateStatus {
	status := TLSCertificateStatus{Status: "unknown"}
	if s.mainConfig == nil {
		status.Message = "No configuration is available to this process."
		return status
	}

	status.Enabled = s.mainConfig.TLSEnabled
	path := strings.TrimSpace(s.mainConfig.TLSCertFile)
	if path == "" {
		// Not an error. A server that only accepts plaintext on a private
		// network has nothing to report, and inventing a warning for it would
		// train operators to ignore this panel.
		status.Message = "No certificate is configured."
		return status
	}

	status.Configured = true
	status.Path = path

	cert, err := readLeafCertificate(path)
	if err != nil {
		status.Status = "critical"
		// TLS switched on with a certificate that cannot be read is a server
		// that will fail to start or fail every handshake, so it is not a
		// quiet condition.
		status.Message = fmt.Sprintf("The certificate at %s could not be read: %v", path, err)
		return status
	}

	status.Subject = cert.Subject.String()
	status.Issuer = cert.Issuer.String()
	status.DNSNames = cert.DNSNames
	status.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	status.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	status.SelfSigned = cert.Subject.String() == cert.Issuer.String()

	// Rounded down: a certificate with 13.9 days left has 13, not 14. Rounding
	// the other way would let it report the safe side of a threshold it has
	// already crossed.
	remaining := time.Until(cert.NotAfter)
	status.DaysRemaining = int(remaining.Hours() / 24)

	switch {
	case remaining <= 0:
		status.Expired = true
		status.Status = "expired"
		status.Message = fmt.Sprintf("Expired on %s. Sending servers will refuse to deliver over TLS.",
			cert.NotAfter.UTC().Format("2 January 2006"))
	case status.DaysRemaining <= certCriticalDays:
		status.Status = "critical"
		status.Message = fmt.Sprintf("Expires in %s — renew now.", humanDays(status.DaysRemaining))
	case status.DaysRemaining <= certWarnDays:
		status.Status = "warning"
		status.Message = fmt.Sprintf("Expires in %s, on %s.",
			humanDays(status.DaysRemaining), cert.NotAfter.UTC().Format("2 January 2006"))
	default:
		status.Status = "ok"
		status.Message = fmt.Sprintf("Valid until %s (%s).",
			cert.NotAfter.UTC().Format("2 January 2006"), humanDays(status.DaysRemaining))
	}

	// A certificate that is not valid yet fails handshakes just as thoroughly
	// as an expired one, and is easy to produce by getting a clock wrong.
	if time.Now().Before(cert.NotBefore) {
		status.Status = "critical"
		status.Message = fmt.Sprintf("Not valid until %s; handshakes will fail until then.",
			cert.NotBefore.UTC().Format("2 January 2006"))
	}

	if status.SelfSigned && status.Status == "ok" {
		status.Message += " Self-signed, so other servers will not trust it."
	}

	return status
}

func humanDays(days int) string {
	switch {
	case days <= 0:
		return "less than a day"
	case days == 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", days)
	}
}

// readLeafCertificate returns the first certificate in a PEM file.
//
// The first is the leaf by convention, and it is the one whose dates matter:
// an intermediate outliving the leaf tells the operator nothing useful.
func readLeafCertificate(path string) (*x509.Certificate, error) {
	// #nosec G304 -- the path comes from the server's own configuration, read
	// at startup; no request supplies it.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue // a key in the same file, which is common enough
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("no certificate found in the file")
}
