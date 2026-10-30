package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// writeNamedCert writes a certificate for names at path, valid for days.
func writeNamedCert(t *testing.T, path string, days int, names ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertificatesReportListsEveryServedCertificate(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "cert.pem")
	sni := filepath.Join(dir, "sni")
	writeNamedCert(t, primary, 60, "dev.example.com")
	writeNamedCert(t, filepath.Join(sni, "mail.example.net", "cert.pem"), 5, "mail.example.net")
	s := &Server{mainConfig: &MainConfig{
		TLSCertFile: primary, TLSSNIDir: sni,
		LocalDomains: []string{"localhost", "example.org", "example.net", "dev.example.com"},
	}}

	r := s.certificatesReport()
	if len(r.Certificates) != 2 || !r.Certificates[0].Primary || r.Certificates[1].Label != "mail.example.net" {
		t.Fatalf("certificates = %+v", r.Certificates)
	}
	if r.Certificates[1].Status != "warning" {
		t.Errorf("a certificate with 5 days left should warn, got %q", r.Certificates[1].Status)
	}

	got := map[string]DomainCertificate{}
	for _, d := range r.Domains {
		got[d.Domain] = d
	}
	if _, ok := got["localhost"]; ok {
		t.Error("localhost needs no certificate and shouldn't be listed")
	}
	if d := got["dev.example.com"]; d.Host != "dev.example.com" || d.Label != "primary" || d.Status != "ok" {
		t.Errorf("dev.example.com = %+v", d)
	}
	if d := got["example.net"]; d.Host != "mail.example.net" || d.Label != "mail.example.net" || d.Status != "warning" {
		t.Errorf("example.net = %+v", d)
	}
	if d := got["example.org"]; d.Status != "missing" || d.Host != "" {
		t.Errorf("a domain no certificate names should be missing, got %+v", d)
	}
}

func TestCertCoversWildcardOneLabel(t *testing.T) {
	names := []string{"*.example.net"}
	if !certCovers(names, "mail.example.net") {
		t.Error("a wildcard should cover one label")
	}
	if certCovers(names, "example.net") || certCovers(names, "a.mail.example.net") {
		t.Error("a wildcard covers exactly one label")
	}
}

// managedServer is a server whose certificate requests go to a temporary
// directory laid out as the cloud deployment's, with status.json saying
// mail.example.net is set by the deployment.
func managedServer(t *testing.T) (*Server, *certManager) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "requests"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := `{"primary": "dev.example.com", "configured": ["mail.example.net"], "requested": [], "uploaded": [], "pending": [], "rejected": []}`
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(certManageEnv, dir)
	return &Server{mainConfig: &MainConfig{LocalDomains: []string{"dev.example.com"}}}, &certManager{dir: dir}
}

func jsonRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestCertificateManagementUnavailableWithoutDirectory(t *testing.T) {
	t.Setenv(certManageEnv, "")
	s := &Server{mainConfig: &MainConfig{}}
	for _, h := range []http.HandlerFunc{s.handleTLSCertificateSync, s.handleTLSCertificateRequest, s.handleTLSCertificateUpload} {
		rec := httptest.NewRecorder()
		h(rec, jsonRequest(http.MethodPost, "/", `{}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("without the directory a write should be unavailable, got %d", rec.Code)
		}
	}
	if s.certificatesReport().ManageAvailable {
		t.Error("the report shouldn't offer management without the directory")
	}
}

func TestCertificateRequestAndRemove(t *testing.T) {
	s, m := managedServer(t)
	for body, want := range map[string]int{
		`{"host": "Mail.Example.org."}`: http.StatusOK,
		`{"host": "mail.example.org"}`:  http.StatusConflict, // already requested
		`{"host": "dev.example.com"}`:   http.StatusConflict, // the primary
		`{"host": "mail.example.net"}`:  http.StatusConflict, // set by the deployment
		`{"host": "bad_host"}`:          http.StatusBadRequest,
		`{"host": "nodot"}`:             http.StatusBadRequest,
	} {
		rec := httptest.NewRecorder()
		s.handleTLSCertificateRequest(rec, jsonRequest(http.MethodPost, "/api/tls/certificates", body))
		if rec.Code != want {
			t.Errorf("request %s = %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
	hosts, err := m.hosts()
	if err != nil || len(hosts) != 1 || hosts[0] != "mail.example.org" {
		t.Fatalf("hosts = %v %v", hosts, err)
	}
	if _, err := os.Stat(filepath.Join(m.requests(), "request")); err != nil {
		t.Error("a request should trigger the host's sync")
	}
	if r := s.certificatesReport(); len(r.Pending) != 1 || r.Pending[0] != "mail.example.org" {
		t.Errorf("a requested host without a certificate should be pending, got %v", r.Pending)
	}

	del := func(host string) int {
		rec := httptest.NewRecorder()
		s.handleTLSCertificateDelete(rec, mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"host": host}))
		return rec.Code
	}
	if code := del("mail.example.net"); code != http.StatusConflict {
		t.Errorf("deleting a configured host = %d, want 409", code)
	}
	if code := del("mail.example.org"); code != http.StatusOK {
		t.Errorf("deleting a requested host = %d", code)
	}
	if code := del("mail.example.org"); code != http.StatusNotFound {
		t.Errorf("deleting it again = %d, want 404", code)
	}
	if hosts, _ := m.hosts(); len(hosts) != 0 {
		t.Errorf("hosts after removal = %v", hosts)
	}
}

func TestCertificateUpload(t *testing.T) {
	s, m := managedServer(t)
	certPEM, keyPEM := pemPair(t, 30, "*.example.org")
	body, _ := json.Marshal(map[string]string{"certificate": string(certPEM), "key": string(keyPEM)})
	rec := httptest.NewRecorder()
	s.handleTLSCertificateUpload(rec, jsonRequest(http.MethodPost, "/api/tls/certificates/upload", string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body.String())
	}
	// A wildcard is filed under a name it covers.
	if !m.uploaded("wildcard.example.org") {
		t.Fatal("the upload should be stored under wildcard.example.org")
	}
	if data, err := os.ReadFile(filepath.Join(m.uploads(), "wildcard.example.org", "key.pem")); err != nil || string(data) != string(keyPEM) {
		t.Fatalf("stored key = %v", err)
	}

	// A key from another pair is refused before anything is written.
	_, otherKey := pemPair(t, 30, "mail.example.com")
	body, _ = json.Marshal(map[string]string{"certificate": string(certPEM), "key": string(otherKey)})
	rec = httptest.NewRecorder()
	s.handleTLSCertificateUpload(rec, jsonRequest(http.MethodPost, "/api/tls/certificates/upload", string(body)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a mismatched key = %d, want 400", rec.Code)
	}

	// The deployment's own hosts can't be replaced by an upload.
	certPEM, keyPEM = pemPair(t, 30, "mail.example.net")
	body, _ = json.Marshal(map[string]string{"certificate": string(certPEM), "key": string(keyPEM)})
	rec = httptest.NewRecorder()
	s.handleTLSCertificateUpload(rec, jsonRequest(http.MethodPost, "/api/tls/certificates/upload", string(body)))
	if rec.Code != http.StatusConflict {
		t.Errorf("uploading over a configured host = %d, want 409", rec.Code)
	}

	// Expired certificates are refused.
	certPEM, keyPEM = pemPair(t, -1, "old.example.org")
	body, _ = json.Marshal(map[string]string{"certificate": string(certPEM), "key": string(keyPEM)})
	rec = httptest.NewRecorder()
	s.handleTLSCertificateUpload(rec, jsonRequest(http.MethodPost, "/api/tls/certificates/upload", string(body)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an expired certificate = %d, want 400", rec.Code)
	}
}

// pemPair returns a certificate for names valid for days (negative: already
// expired) and its key.
func pemPair(t *testing.T, days int, names ...string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	start := time.Now().Add(-time.Hour)
	if days < 0 {
		start = end.Add(-24 * time.Hour)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: start, NotAfter: end}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
