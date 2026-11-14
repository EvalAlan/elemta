package config

import (
	"path/filepath"
	"testing"

	"github.com/EvalAlan/elemta/internal/smtp"
)

// TestStartupWarnings pins which startup warnings each service sees. The
// one shared config names the SMTP certificate and key; only the SMTP node
// is given them, so only a process that serves SMTP is warned they are
// missing. A one-second queue interval is the shipped setting and isn't
// warned about anywhere.
func TestStartupWarnings(t *testing.T) {
	dir := t.TempDir()
	c := DefaultConfig()
	if c.TLS == nil {
		c.TLS = &smtp.TLSConfig{}
	}
	c.TLS.CertFile = filepath.Join(dir, "cert.pem")
	c.TLS.KeyFile = filepath.Join(dir, "key.pem")
	c.QueueProcessor.Interval = 1
	r := c.Validate()

	fields := func(ws []ValidationError) map[string]bool {
		m := map[string]bool{}
		for _, w := range ws {
			m[w.Field] = true
		}
		return m
	}
	smtp := fields(r.WarningsFor(LoadOptions{}))
	if !smtp["tls.cert_file"] || !smtp["tls.key_file"] {
		t.Errorf("the SMTP node isn't warned its certificate is missing: %v", smtp)
	}
	web := fields(r.WarningsFor(LoadOptions{NoSMTP: true}))
	if web["tls.cert_file"] || web["tls.key_file"] {
		t.Errorf("the webmail is warned about SMTP files it never opens: %v", web)
	}
	if smtp["queue_processor.interval"] || web["queue_processor.interval"] {
		t.Error("the shipped one-second queue interval is warned about")
	}
	if len(r.Warnings) != len(r.WarningsFor(LoadOptions{})) {
		t.Error("WarningsFor dropped a warning for a process that serves SMTP")
	}
}
