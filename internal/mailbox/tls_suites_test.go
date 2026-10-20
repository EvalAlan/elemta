package mailbox

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestMailTLSSuitesAreAEADOnly(t *testing.T) {
	names := map[uint16]string{}
	for _, s := range tls.CipherSuites() {
		names[s.ID] = s.Name
	}
	for _, s := range tls.InsecureCipherSuites() {
		names[s.ID] = s.Name
	}
	for _, id := range tls12Suites {
		name := names[id]
		if !strings.HasPrefix(name, "TLS_ECDHE_") || !(strings.Contains(name, "_GCM_") || strings.Contains(name, "CHACHA20")) {
			t.Errorf("%s (%#04x) is not forward-secret AEAD", name, id)
		}
	}
}
