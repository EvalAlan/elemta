package queue

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/EvalAlan/elemta/internal/dkim"
)

func testSigner(t *testing.T) *dkim.Signer {
	t.Helper()
	key, err := dkim.GenerateKey("ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.key")
	if err := dkim.WritePrivateKey(path, key); err != nil {
		t.Fatal(err)
	}
	s, err := dkim.NewSigner(&dkim.Config{Enabled: true, Domains: []dkim.DomainConfig{{
		Domain: "example.com", Selector: "s2", PrivateKeyPath: path,
	}}}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Config reload swaps the signer through the processor, including when the
// remote handler sits inside the split router.
func TestProcessorSetDKIMSignerReachesTheRemoteHandler(t *testing.T) {
	signer := testSigner(t)

	direct := NewSMTPDeliveryHandler(0)
	p := &Processor{handler: direct}
	if !p.SetDKIMSigner(signer) || direct.currentSigner() == nil {
		t.Fatal("signer did not reach the SMTP handler")
	}
	p.SetDKIMSigner(nil)
	if direct.currentSigner() != nil {
		t.Fatal("turning signing off did not clear the signer")
	}

	remote := NewSMTPDeliveryHandler(0)
	split := &Processor{handler: NewSplitDeliveryHandler(NewMockDeliveryHandler(0), remote, []string{"local.example"}, slog.Default())}
	if !split.SetDKIMSigner(signer) || remote.currentSigner() == nil {
		t.Fatal("signer did not reach the remote handler inside the split router")
	}

	lmtp := &Processor{handler: NewMockDeliveryHandler(0)}
	if lmtp.SetDKIMSigner(signer) {
		t.Error("a handler that never signs reported that it took the signer")
	}
}
