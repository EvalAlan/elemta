package smtp

import (
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// A freshly issued Let's Encrypt certificate has under 90 days left, and used
// to raise a "low" alert on every start. Only a certificate whose renewal is
// overdue is worth anyone's attention, and that is now emailed.
func TestCertificateAlertsEmailOverdueRenewals(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cm := NewCertificateMonitor(logger, NewDefaultCertificateAlerter(logger))
	var mu sync.Mutex
	var sent []string
	cm.SetNotifier(func(subject, body string) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, subject+"\n"+body)
	})

	cm.MonitorCertificate("fresh.example", generateTestCertificateForSecurity(t, "fresh.example", time.Now().Add(67*24*time.Hour)))
	cm.MonitorCertificate("renewing.example", generateTestCertificateForSecurity(t, "renewing.example", time.Now().Add(28*24*time.Hour)))
	if st := cm.certificates["fresh.example"]; len(st.Alerts) != 0 {
		t.Fatalf("67 days left raised %+v", st.Alerts)
	}
	if len(sent) != 0 {
		t.Fatalf("emailed about certificates still due for renewal: %v", sent)
	}

	cm.MonitorCertificate("stuck.example", generateTestCertificateForSecurity(t, "stuck.example", time.Now().Add(15*24*time.Hour)))
	if len(sent) != 1 || !strings.Contains(sent[0], "Certificate problem: Certificate for stuck.example expires in") || !strings.Contains(sent[0], "elemta-cert-sync") {
		t.Fatalf("overdue renewal: %v", sent)
	}
	// The hourly check doesn't repeat it within a day.
	cm.CheckAllCertificates()
	if len(sent) != 1 {
		t.Fatalf("repeated within a day: %d emails", len(sent))
	}
}
