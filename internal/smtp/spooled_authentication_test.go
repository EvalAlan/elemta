package smtp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/arc"
	"github.com/EvalAlan/elemta/internal/authresult"
	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/queue"
)

type spoolAuthResolver struct {
	authresult.Resolver
	record string
}

func (r spoolAuthResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{r.record}, nil
}

func TestProcessSpoolVerifiesCompleteSignedBody(t *testing.T) {
	keyPath := writeDeliveryTestDKIMKey(t)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyBytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&parsed.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := spoolAuthResolver{record: "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)}
	signer, err := dkim.NewSigner(&dkim.Config{Enabled: true, Domains: []dkim.DomainConfig{{Domain: "example.com", Selector: "dkim", PrivateKeyPath: keyPath}}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: sender@example.com\r\nTo: user@example.com\r\nDate: Sun, 18 Oct 2026 19:00:00 +0000\r\nSubject: large signed message\r\n\r\n" + strings.Repeat("original body line\r\n", 40000))
	signed, err := signer.Sign(message, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := arc.New(arc.Config{Enabled: true, Seal: true, Domain: "example.com", Selector: "arc", PrivateKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(t.Context(), signed, "example.com; dkim=pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) <= DefaultHeadSize {
		t.Fatal("fixture must exceed the message preview")
	}
	for _, threshold := range []int64{0, -1} {
		for _, tamper := range []bool{false, true} {
			cfg := createTestConfig(t)
			server, err := NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer server.Close()
				session := NewSession(t.Context(), &fakeConn{remote: &mockAddr{addr: "127.0.0.1:12345"}}, cfg, nil)
				defer session.cancel()
				session.SetQueueManager(server.queueManager)
				session.SetAuthVerifier(authresult.New(authresult.Config{Enabled: true, DKIMEnabled: true, ARCEnabled: true, Resolver: resolver}))
				if err := session.state.SetMailFrom(t.Context(), "sender@example.com"); err != nil {
					t.Fatal(err)
				}
				if err := session.state.AddRecipient(t.Context(), "user@example.com"); err != nil {
					t.Fatal(err)
				}
				spool := NewMessageSpool(t.TempDir(), threshold)
				defer spool.Close()
				data := bytes.Clone(sealed)
				if tamper {
					data[len(data)-10] ^= 1
				}
				if _, err := spool.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := session.dataHandler.ProcessMessage(t.Context(), spool); err != nil {
					t.Fatal(err)
				}
				results, checked := session.AuthResults()
				want := "pass"
				if tamper {
					want = "fail"
				}
				if !checked || len(results.DKIM) != 1 || results.DKIM[0].Value != want || results.ARC.Value != want {
					t.Fatalf("threshold=%d tamper=%v: DKIM=%+v ARC=%+v", threshold, tamper, results.DKIM, results.ARC)
				}
				queued, err := server.queueManager.ListMessages(queue.Active)
				if err != nil || len(queued) != 1 {
					t.Fatalf("queue count=%d err=%v", len(queued), err)
				}
				content, err := server.queueManager.GetMessageContent(queued[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasSuffix(content, data) {
					t.Fatal("verification changed original signed bytes")
				}
			}()
		}
	}
}
