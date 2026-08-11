package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"encoding/base64"

	"github.com/gorilla/mux"
)

func mailAuthTestKey(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicDER)
	return path, record
}

func TestMailAuthDNSPreflightUsesTypedPlugin(t *testing.T) {
	s := &Server{
		mainConfig: &MainConfig{SPF: &SPFStatus{Enabled: true}},
		mailAuthLookupTXT: func(_ context.Context, name string) ([]string, error) {
			if name != "pass.auth.test" {
				t.Fatalf("lookup = %q", name)
			}
			return []string{"unrelated", "v=spf1 +all"}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/config/plugins/spf/check", strings.NewReader(`{"domain":"pass.auth.test"}`))
	req = mux.SetURLVars(req, map[string]string{"plugin": "spf"})
	rec := httptest.NewRecorder()
	s.handleCheckMailAuthPlugin(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"published":true`) {
		t.Fatalf("preflight = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMailAuthDNSPreflightReportsMissingRecord(t *testing.T) {
	s := &Server{
		mainConfig: &MainConfig{DMARC: &DMARCStatus{Enabled: true}},
		mailAuthLookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"something else"}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/config/plugins/dmarc/check", strings.NewReader(`{"domain":"pass.auth.test"}`))
	req = mux.SetURLVars(req, map[string]string{"plugin": "dmarc"})
	rec := httptest.NewRecorder()
	s.handleCheckMailAuthPlugin(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"published":false`) {
		t.Fatalf("preflight = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMailAuthDNSPreflightRequiresPublishedKeyToMatch(t *testing.T) {
	dir := t.TempDir()
	privatePath, matchingRecord := mailAuthTestKey(t, dir, "configured.key")
	_, differentRecord := mailAuthTestKey(t, dir, "different.key")
	s := &Server{
		mainConfig: &MainConfig{DKIM: &DKIMStatus{Domains: []SigningDomainStatus{{
			Domain: "example.com", Selector: "mail", PrivateKeyPath: privatePath,
		}}}},
	}
	check := func(record string) *httptest.ResponseRecorder {
		s.mailAuthLookupTXT = func(_ context.Context, name string) ([]string, error) {
			if name != "mail._domainkey.example.com" {
				t.Fatalf("lookup = %q", name)
			}
			return []string{record}, nil
		}
		req := httptest.NewRequest(http.MethodPost, "/api/config/plugins/dkim/check", strings.NewReader(`{"domain":"example.com"}`))
		req = mux.SetURLVars(req, map[string]string{"plugin": "dkim"})
		rec := httptest.NewRecorder()
		s.handleCheckMailAuthPlugin(rec, req)
		return rec
	}

	if rec := check(matchingRecord); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"key_matches_dns":true`) {
		t.Fatalf("matching key preflight = %d %s", rec.Code, rec.Body.String())
	}
	if rec := check(differentRecord); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "does not match") {
		t.Fatalf("mismatched key preflight = %d %s", rec.Code, rec.Body.String())
	}
}
