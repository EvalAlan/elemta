package smtp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/logging"
	"github.com/EvalAlan/elemta/internal/queue"
	msgdkim "github.com/emersion/go-msgauth/dkim"
)

// Mail a signed-in user sends is signed as it's queued, for every recipient,
// so a copy delivered here and forwarded later still carries its author's
// signature. Mail from outside isn't: its signatures are its sender's.
func TestSubmissionIsSignedWhenQueued(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "dkim.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := dkim.NewSigner(&dkim.Config{Enabled: true, Domains: []dkim.DomainConfig{{Domain: "example.com", Selector: "s1", PrivateKeyPath: keyPath}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER)

	message := "From: Alan <alan@example.com>\r\nTo: <alan@other.example>\r\nSubject: TESTER!\r\nDate: Tue, 03 Nov 2026 02:13:33 +0000\r\nMessage-ID: <t1@example.com>\r\n\r\nFrom the start of a line\r\nhello\r\n"
	hop := []byte("Received: from webmail.localhost by mail.example.com with ESMTPSA\r\n")

	queued := func(t *testing.T, authenticated bool, from string) (string, queue.Message) {
		t.Helper()
		mgr := queue.NewManager(t.TempDir(), 0)
		state := NewSessionState(quietLogger())
		state.SetAuthenticated(t.Context(), authenticated, "alan@example.com")
		dh := &DataHandler{
			session:      &Session{state: state, logger: quietLogger(), remoteAddr: "10.0.0.5:1234", dkimSigner: signer},
			state:        state,
			logger:       quietLogger(),
			config:       &Config{Hostname: "mail.example.com"},
			queueManager: mgr,
			msgLogger:    logging.NewMessageLogger(quietLogger()),
		}
		body := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(message)), nil }
		meta := &MessageMetadata{From: from, To: []string{"alan@other.example"}, Subject: "TESTER!"}
		if err := dh.saveMessage(t.Context(), hop, body, meta); err != nil {
			t.Fatal(err)
		}
		all, err := mgr.GetAllMessages()
		if err != nil || len(all) != 1 {
			t.Fatalf("queued %d, %v", len(all), err)
		}
		content, err := mgr.GetMessageContent(all[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := mgr.GetMessage(all[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		return string(content), msg
	}

	content, msg := queued(t, true, "alan@example.com")
	if !strings.HasPrefix(content, "DKIM-Signature:") || !strings.Contains(content, "d=example.com") || !strings.Contains(content, string(hop)) {
		t.Fatalf("submission not signed:\n%s", content)
	}
	if msg.Annotations[queue.AnnotationDKIMSigned] != "example.com" {
		t.Errorf("annotations = %v", msg.Annotations)
	}
	// It verifies as queued, and after a forward adds headers above it.
	forwarded := "Received: from mailbox by mail.example.com with ESMTP\r\nX-Elemta-Sieve-Redirected-By: alan@other.example\r\n" + content
	vs, err := msgdkim.VerifyWithOptions(bytes.NewReader([]byte(forwarded)), &msgdkim.VerifyOptions{LookupTXT: func(name string) ([]string, error) {
		if name == "s1._domainkey.example.com" {
			return []string{record}, nil
		}
		return nil, fmt.Errorf("no record for %s", name)
	}})
	if err != nil || len(vs) != 1 || vs[0].Err != nil || vs[0].Domain != "example.com" {
		t.Fatalf("verification after forwarding: %+v %v", vs, err)
	}

	// From outside, or for a domain without a key: queued as received.
	for _, c := range []struct {
		authenticated bool
		from          string
	}{{false, "alan@example.com"}, {true, "alan@nokey.example"}, {true, ""}} {
		content, msg := queued(t, c.authenticated, c.from)
		if strings.Contains(content, "DKIM-Signature:") || msg.Annotations[queue.AnnotationDKIMSigned] != "" {
			t.Errorf("authenticated=%v from=%q was signed:\n%s", c.authenticated, c.from, content)
		}
	}
}
