package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/authresult"
	"github.com/EvalAlan/elemta/internal/datasource"
	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/queue"
	msgdkim "github.com/emersion/go-msgauth/dkim"
	"github.com/stretchr/testify/require"
)

// End-to-end checks of what leaves the server signed. A real server takes
// each message over SMTP (with a real AUTH and real submission signing),
// the message is read back from the queue with its annotations, and
// delivery's own signing step decides what the recipient would get. The
// DKIM-Signature on that output is verified against the test keys.
//
// They pin the fixes for mail going out under a signature it shouldn't
// carry: SF-07 (signing by a message's own From), SF-08 (From not bound to
// the login) and SF-12's forward case, together.

type signingKeys struct {
	cfg     *dkim.Config
	records map[string]string // domain -> TXT record at s1._domainkey
}

func newSigningKeys(t *testing.T, domains ...string) signingKeys {
	t.Helper()
	k := signingKeys{cfg: &dkim.Config{Enabled: true}, records: map[string]string{}}
	for _, d := range domains {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), d+".key")
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
		pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		k.cfg.Domains = append(k.cfg.Domains, dkim.DomainConfig{Domain: d, Selector: "s1", PrivateKeyPath: path})
		k.records["s1._domainkey."+d] = "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
	}
	return k
}

// verifiedDomains returns the d= of every DKIM signature on raw that
// verifies against the test keys.
func (k signingKeys) verifiedDomains(t *testing.T, raw []byte) []string {
	t.Helper()
	verifications, err := msgdkim.VerifyWithOptions(bytes.NewReader(raw), &msgdkim.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			if r, ok := k.records[strings.TrimSuffix(name, ".")]; ok {
				return []string{r}, nil
			}
			return nil, &net.DNSError{Name: name, Err: "no record", IsNotFound: true}
		},
	})
	require.NoError(t, err)
	var out []string
	for _, v := range verifications {
		if v.Err == nil {
			out = append(out, v.Domain)
		}
	}
	return out
}

func TestEndToEndSigning(t *testing.T) {
	old := newAuthDataSource
	t.Cleanup(func() { newAuthDataSource = old })
	newAuthDataSource = func(datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{authenticateFn: func(_ context.Context, u, p string) (bool, error) {
			return u == "dana@example.com" && p == "correct horse", nil
		}}, nil
	}
	keys := newSigningKeys(t, "example.com", "other.example")
	cfg := createTestConfig(t)
	cfg.SubmissionAddr = "127.0.0.1:0" // logins are taken on the submission listener only
	cfg.LocalDomains = []string{"example.com", "other.example"}
	cfg.Auth = &AuthConfig{Enabled: true, DataSourceName: "ldap", DataSourceHost: "ldap.internal"}
	cfg.DKIM = keys.cfg
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	signer, err := dkim.NewSigner(keys.cfg, nil)
	require.NoError(t, err)
	delivery := queue.NewSMTPDeliveryHandler(0)
	delivery.SetDKIMSigner(signer)
	mgr := queue.NewManager(cfg.QueueDir, 0)
	seen := map[string]bool{}
	// sent submits one message and returns what delivery would send, or
	// the refusal.
	sent := func(t *testing.T, signIn bool, mailFrom, message string) (out []byte, refusal string) {
		t.Helper()
		p := dialProbe(t, server.getSubmissionListener().Addr().String())
		p.cmd("EHLO client.example")
		if signIn {
			plain := base64.StdEncoding.EncodeToString([]byte("\x00dana@example.com\x00correct horse"))
			if r := p.cmd("AUTH PLAIN " + plain); !strings.HasPrefix(r, "235") {
				t.Fatalf("AUTH: %q", r)
			}
		}
		if r := p.cmd("MAIL FROM:<" + mailFrom + ">"); !strings.HasPrefix(r, "250") {
			return nil, r
		}
		if r := p.cmd("RCPT TO:<someone@remote.example>"); !strings.HasPrefix(r, "250") {
			t.Fatalf("RCPT: %q", r)
		}
		if r := p.cmd("DATA"); !strings.HasPrefix(r, "354") {
			t.Fatalf("DATA: %q", r)
		}
		if r := p.cmd(message + "\r\n."); !strings.HasPrefix(r, "250") {
			return nil, r
		}
		all, err := mgr.GetAllMessages()
		require.NoError(t, err)
		for _, m := range all {
			if seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			content, err := mgr.GetMessageContent(m.ID)
			require.NoError(t, err)
			out, err := delivery.SignForDelivery(m, content)
			require.NoError(t, err)
			return out, ""
		}
		t.Fatal("accepted but not queued")
		return nil, ""
	}
	body := "\r\nSubject: hello\r\nDate: Fri, 13 Nov 2026 10:00:00 +0000\r\nMessage-ID: <x@example.com>\r\n\r\nhi\r\n"

	t.Run("signed-in user, own From: signed for their domain", func(t *testing.T) {
		out, refusal := sent(t, true, "dana@example.com", "From: Dana <dana@example.com>"+body)
		require.Empty(t, refusal)
		require.Contains(t, keys.verifiedDomains(t, out), "example.com")
	})
	t.Run("signed-in user, a colleague's From: refused (SF-08)", func(t *testing.T) {
		_, refusal := sent(t, true, "dana@example.com", "From: CEO <ceo@example.com>"+body)
		require.True(t, strings.HasPrefix(refusal, "550"), refusal)
	})
	t.Run("signed-in user, null sender, another tenant's From: refused (SF-07/08)", func(t *testing.T) {
		_, refusal := sent(t, true, "", "From: CEO <ceo@other.example>"+body)
		require.True(t, strings.HasPrefix(refusal, "550"), refusal)
	})
	t.Run("signed-in user, null sender, own From: signed", func(t *testing.T) {
		out, refusal := sent(t, true, "", "From: dana@example.com"+body)
		require.Empty(t, refusal)
		require.Contains(t, keys.verifiedDomains(t, out), "example.com")
	})
	t.Run("own relay, out-of-office reply: signed for its From", func(t *testing.T) {
		out, refusal := sent(t, false, "", "From: dana@example.com\r\nAuto-Submitted: auto-replied"+body)
		require.Empty(t, refusal)
		require.Contains(t, keys.verifiedDomains(t, out), "example.com")
	})
	t.Run("own relay, Sieve forward of someone else's From: not signed (SF-07)", func(t *testing.T) {
		out, refusal := sent(t, false, "", mailpolicy.SieveRedirectHeader+": dana@example.com\r\nFrom: CEO <ceo@other.example>"+body)
		require.Empty(t, refusal)
		require.Empty(t, keys.verifiedDomains(t, out), "a forward was signed for the From it carries")
	})
}

// SF-17 with the real verifier: mail from outside that claims a local domain
// publishing p=reject, and fails DMARC, is refused with enforcement off; the
// same mail from the operator's own relay isn't.
func TestOwnDomainForgeryRefusedByTheVerifier(t *testing.T) {
	message := []byte("From: ceo@example.com\r\nSubject: wire it\r\n\r\nbody\r\n")
	for _, tc := range []struct {
		peer    string
		refused bool
	}{
		{"203.0.113.5:12345", true},
		{"127.0.0.1:12345", false},
	} {
		state := NewSessionState(quietLogger())
		cfg := &Config{LocalDomains: []string{"example.com"}}
		session := &Session{
			state: state, logger: quietLogger(), remoteAddr: tc.peer, config: cfg,
			authVerifier: authresult.New(authresult.Config{
				Enabled: true, EnforceDMARC: false, Resolver: &submissionAuthResolver{Resolver: net.DefaultResolver},
			}),
		}
		session.commandHandler = &CommandHandler{session: session, state: state, config: cfg,
			conn: fakeAddrConn{remote: mustTCPAddr(t, tc.peer)}, logger: quietLogger()}
		err := session.VerifyAuthentication(t.Context(), "ceo@example.com", message)
		if tc.refused && (err == nil || !strings.HasPrefix(err.Error(), "550")) {
			t.Errorf("%s: forged own-domain mail accepted: %v", tc.peer, err)
		}
		if !tc.refused && err != nil {
			t.Errorf("%s: the operator's relay was refused: %v", tc.peer, err)
		}
	}
}

func mustTCPAddr(t *testing.T, hostport string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", hostport)
	require.NoError(t, err)
	return a
}
