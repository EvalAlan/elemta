package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/EvalAlan/elemta/internal/provision"
)

// Every certificate the mail services serve, whether each local domain has
// one, and the requests that change them.
//
// A server that hosts several domains serves its primary certificate plus
// one per extra mail host, chosen by the name the client asks for
// (internal/tlssni). Each of those expires on its own schedule, and a domain
// added without its certificate fails quietly: mail apps for it are handed
// the primary certificate and refuse it, while everything else keeps
// working. This page is where both show up.
//
// The console doesn't obtain, install or serve certificates itself, and
// never talks to Caddy. On the cloud dev server it writes requests into a
// directory the host watches (ELEMTA_CERT_MANAGE_DIR):
//
//	requests/hosts                 host names to get Let's Encrypt certificates for
//	requests/uploads/<host>/*.pem  certificates uploaded here
//	requests/request               touched to ask the host to apply them now
//	status.json                    what the host applied, written by the host
//
// scripts/cloud-sync-certs.sh, run by a path unit on the host, checks every
// request again before acting on it. Without the directory the page is
// read-only.

// certManageEnv names the directory shared with the host's certificate sync.
const certManageEnv = "ELEMTA_CERT_MANAGE_DIR"

// certHost matches the host names the host's script accepts, so a request it
// would reject is refused here with a reason instead.
var certHost = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ServedCertificate is one certificate file the mail services serve.
type ServedCertificate struct {
	// Label is "primary" or the name of its directory under the SNI root.
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	// Source is primary, configured (the deployment's settings), requested
	// (Let's Encrypt, asked for here), uploaded, or unknown.
	Source string `json:"source"`
	// Removable is whether this console can delete it.
	Removable bool `json:"removable"`
	TLSCertificateStatus
}

// DomainCertificate says which served certificate a local domain's clients
// get. Clients use either the domain itself or mail.<domain> as the host.
type DomainCertificate struct {
	Domain string `json:"domain"`
	// Host is the name the certificate covers, empty when none does.
	Host  string `json:"host,omitempty"`
	Label string `json:"label,omitempty"`
	// Status is ok, warning, critical, expired or missing.
	Status string `json:"status"`
}

// CertificateRejection is a request the host refused, with its reason.
type CertificateRejection struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// CertificatesReport is the Certificates page.
type CertificatesReport struct {
	Certificates []ServedCertificate `json:"certificates"`
	Domains      []DomainCertificate `json:"domains"`
	// ManageAvailable is whether this deployment takes requests from here.
	ManageAvailable bool `json:"manage_available"`
	// Pending are requested hosts without a certificate yet.
	Pending  []string               `json:"pending"`
	Rejected []CertificateRejection `json:"rejected"`
	// AppliedAt is when the host last applied the requests.
	AppliedAt string `json:"applied_at,omitempty"`
	Message   string `json:"message,omitempty"`
}

// certSyncStatus is status.json, written by the host's sync.
type certSyncStatus struct {
	AppliedAt string `json:"applied_at"`
	Primary   string `json:"primary"`
	// Deployment is MAIL_DOMAIN, which stays the deployment's whichever
	// certificate is the default.
	Deployment string                 `json:"deployment"`
	Configured []string               `json:"configured"`
	Requested  []string               `json:"requested"`
	Uploaded   []string               `json:"uploaded"`
	Pending    []string               `json:"pending"`
	Rejected   []CertificateRejection `json:"rejected"`
}

type certManager struct{ dir string }

// certManagerFromEnv returns the shared directory, or nil when this
// deployment has none and the page is read-only.
func certManagerFromEnv() *certManager {
	dir := strings.TrimSpace(os.Getenv(certManageEnv))
	if dir == "" {
		return nil
	}
	return &certManager{dir: dir}
}

func (m *certManager) requests() string { return filepath.Join(m.dir, "requests") }

// trigger asks the host to apply the requests now. Only the file's
// modification matters to the path unit.
func (m *certManager) trigger() error {
	return writeFileAtomic(filepath.Join(m.requests(), "request"), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// status is what the host last applied; a deployment that hasn't run the
// sync since the directory appeared has none yet.
func (m *certManager) status() (certSyncStatus, error) {
	var st certSyncStatus
	// #nosec G304 -- a fixed name in the deployment's directory.
	data, err := os.ReadFile(filepath.Join(m.dir, "status.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

func (m *certManager) hosts() ([]string, error) {
	// #nosec G304 -- a fixed name in the deployment's directory.
	f, err := os.Open(filepath.Join(m.requests(), "hosts"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if h := strings.TrimSpace(sc.Text()); h != "" && !strings.HasPrefix(h, "#") {
			out = append(out, h)
		}
	}
	return out, sc.Err()
}

func (m *certManager) setHosts(hosts []string) error {
	var b bytes.Buffer
	b.WriteString("# Written by the admin console's Certificates page.\n")
	for _, h := range hosts {
		b.WriteString(h + "\n")
	}
	// Readable by the host's sync, which runs as another user.
	return writeFileAtomic(filepath.Join(m.requests(), "hosts"), b.Bytes(), 0o644)
}

func (m *certManager) uploads() string { return filepath.Join(m.requests(), "uploads") }

// uploadsRoot opens the uploads directory as an os.Root, so the host names
// used inside it, which arrive in requests, can't reach outside it even if
// one slipped past certHost.
func (m *certManager) uploadsRoot() (*os.Root, error) {
	if err := os.MkdirAll(m.uploads(), 0o755); err != nil { // #nosec G301 -- read by the host's sync, another user
		return nil, err
	}
	return os.OpenRoot(m.uploads())
}

func (m *certManager) uploaded(host string) bool {
	root, err := m.uploadsRoot()
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	_, err = root.Stat(host)
	return err == nil
}

func (m *certManager) removeUpload(host string) error {
	root, err := m.uploadsRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.RemoveAll(host)
}

// writeFileAtomic replaces path, so the host never reads half a file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *Server) handleTLSCertificates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.certificatesReport())
}

func (s *Server) certificatesReport() CertificatesReport {
	report := CertificatesReport{Certificates: []ServedCertificate{}, Domains: []DomainCertificate{}, Pending: []string{}, Rejected: []CertificateRejection{}}
	if s.mainConfig == nil {
		report.Message = "No configuration is available to this process."
		return report
	}
	m := certManagerFromEnv()
	var st certSyncStatus
	if m != nil {
		report.ManageAvailable = true
		var err error
		if st, err = m.status(); err != nil {
			report.Message = fmt.Sprintf("The certificate sync's status could not be read: %v", err)
		}
		report.AppliedAt = st.AppliedAt
		report.Rejected = append(report.Rejected, st.Rejected...)
		// Pending also covers what was asked for since the host last ran.
		want, _ := m.hosts()
		for _, h := range append(append([]string(nil), st.Pending...), want...) {
			if !slices.Contains(report.Pending, h) {
				report.Pending = append(report.Pending, h)
			}
		}
	}
	source := func(label string) string {
		switch {
		case label == st.Deployment, slices.Contains(st.Configured, label):
			return "configured"
		case slices.Contains(st.Requested, label):
			return "requested"
		case slices.Contains(st.Uploaded, label):
			return "uploaded"
		}
		return "unknown"
	}

	if path := strings.TrimSpace(s.mainConfig.TLSCertFile); path != "" {
		report.Certificates = append(report.Certificates, ServedCertificate{Label: "primary", Primary: true, Source: "primary", TLSCertificateStatus: certificateStatus(path)})
	}
	if dir := strings.TrimSpace(s.mainConfig.TLSSNIDir); dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			report.Message = fmt.Sprintf("The certificate directory %s could not be read: %v", dir, err)
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			src := source(e.Name())
			report.Certificates = append(report.Certificates, ServedCertificate{
				Label: e.Name(), Source: src, Removable: m != nil && (src == "requested" || src == "uploaded"),
				TLSCertificateStatus: certificateStatus(filepath.Join(dir, e.Name(), "cert.pem")),
			})
		}
	}
	// A host is pending only until its certificate is served.
	report.Pending = slices.DeleteFunc(report.Pending, func(h string) bool {
		return slices.ContainsFunc(report.Certificates, func(c ServedCertificate) bool { return c.Label == h })
	})
	if len(report.Certificates) == 0 && report.Message == "" {
		report.Message = "No certificate is configured."
	}

	domains := s.localDomains()
	sort.Strings(domains)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || d == "localhost" {
			continue
		}
		report.Domains = append(report.Domains, domainCertificate(d, report.Certificates))
	}
	return report
}

// domainCertificate finds the certificate that serves the domain's mail
// host. The primary is the one a client gets when no other covers the name,
// so it is tried last.
// localDomains reads the file, because domains are added while the console
// runs and it only loads its configuration at start. Without one it has what
// it started with.
func (s *Server) localDomains() []string {
	if s.configPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		names, err := (provision.FileDomains{Path: s.configPath}).List(ctx)
		if err == nil && len(names) > 0 {
			return names
		}
	}
	if s.mainConfig == nil {
		return nil
	}
	return append([]string(nil), s.mainConfig.LocalDomains...)
}

func domainCertificate(domain string, certs []ServedCertificate) DomainCertificate {
	out := DomainCertificate{Domain: domain, Status: "missing"}
	ordered := make([]ServedCertificate, 0, len(certs))
	for _, c := range certs {
		if !c.Primary {
			ordered = append(ordered, c)
		}
	}
	for _, c := range certs {
		if c.Primary {
			ordered = append(ordered, c)
		}
	}
	for _, host := range []string{"mail." + domain, domain} {
		for _, c := range ordered {
			if certCovers(c.DNSNames, host) {
				out.Host, out.Label, out.Status = host, c.Label, c.Status
				return out
			}
		}
	}
	return out
}

// certCovers matches host against a certificate's names, including a
// single-label wildcard as TLS clients do.
func certCovers(names []string, host string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if label, parent, found := strings.Cut(host, "."); found && label != "" && parent == rest {
				return true
			}
		}
	}
	return false
}

// certManagerFor returns the shared directory or answers the request with
// why there is none.
func certManagerFor(w http.ResponseWriter) *certManager {
	m := certManagerFromEnv()
	if m == nil {
		http.Error(w, "Certificates can't be managed from the console on this deployment", http.StatusNotFound)
	}
	return m
}

// reservedCertHost says why host can't be requested, uploaded or removed
// here, or "" when it can be.
func (s *Server) reservedCertHost(m *certManager, host string) string {
	st, _ := m.status()
	primary := st.Primary
	if primary == "" && s.mainConfig != nil && len(s.mainConfig.LocalDomains) > 0 {
		primary = s.mainConfig.LocalDomains[0]
	}
	switch {
	case host == primary:
		return host + " is the primary certificate, set by the deployment."
	case host == st.Deployment:
		return host + " is the deployment's own name, set by its settings."
	case slices.Contains(st.Configured, host):
		return host + " is set by the deployment's settings (EXTRA_MAIL_DOMAINS)."
	}
	return ""
}

// handleTLSCertificateDefault chooses the certificate a client gets when it
// names no host we hold one for. Only the host's sync can check Caddy has it,
// so this records the wish and the sync reports if it can't be met; the
// current default keeps serving until then.
func (s *Server) handleTLSCertificateDefault(w http.ResponseWriter, r *http.Request) {
	m := certManagerFor(w)
	if m == nil {
		return
	}
	var in struct {
		Host string `json:"host"`
	}
	if !decodeJSONBody(w, r, &in) {
		return
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Host)), ".")
	if len(host) > 253 || !certHost.MatchString(host) {
		http.Error(w, "Enter a host name such as mail.example.org.", http.StatusBadRequest)
		return
	}
	if m.uploaded(host) {
		http.Error(w, "An uploaded certificate can't be the default: it isn't renewed, and the default must never lapse.", http.StatusConflict)
		return
	}
	err := writeFileAtomic(filepath.Join(m.requests(), "primary"), []byte(host+"\n"), 0o644)
	if err == nil {
		err = m.trigger()
	}
	if err != nil {
		slog.Error("default certificate request failed", "host", host, "error", err)
		http.Error(w, "The request could not be written", http.StatusInternalServerError)
		return
	}
	slog.Info("default certificate requested", "actor", certActor(r), "host", host)
	writeJSON(w, map[string]string{"status": host + " will be the default certificate within a few seconds."})
}

func certActor(r *http.Request) string {
	if ac := GetAuthContext(r); ac != nil {
		return ac.Username
	}
	return ""
}

// handleTLSCertificateSync asks the host to apply the requests and copy
// renewed certificates now.
func (s *Server) handleTLSCertificateSync(w http.ResponseWriter, r *http.Request) {
	m := certManagerFor(w)
	if m == nil {
		return
	}
	if err := m.trigger(); err != nil {
		slog.Error("certificate sync request failed", "error", err)
		http.Error(w, "The sync request could not be written", http.StatusInternalServerError)
		return
	}
	slog.Info("certificate sync requested", "actor", certActor(r))
	writeJSON(w, map[string]string{"status": "Sync requested. Renewed certificates are copied within a minute."})
}

// handleTLSCertificateRequest asks for a Let's Encrypt certificate for a
// host name.
// maxCertRequest bounds one request: every name is a Let's Encrypt order, and
// failed ones count towards its hourly limit.
const maxCertRequest = 10

// handleTLSCertificateRequest asks for certificates for one or more names, such
// as a mail host and its alternatives. Caddy issues one certificate per name,
// not one naming them all, which clients can't tell apart: the mail services
// pick by the name asked for. The whole request is checked before any of it is
// written, so a typo in the third name doesn't leave the first two requested.
func (s *Server) handleTLSCertificateRequest(w http.ResponseWriter, r *http.Request) {
	m := certManagerFor(w)
	if m == nil {
		return
	}
	var in struct {
		Host  string   `json:"host"`
		Hosts []string `json:"hosts"`
	}
	if !decodeJSONBody(w, r, &in) {
		return
	}
	wanted := []string{}
	for _, raw := range append([]string{in.Host}, in.Hosts...) {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if host != "" && !slices.Contains(wanted, host) {
			wanted = append(wanted, host)
		}
	}
	if len(wanted) == 0 {
		http.Error(w, "Enter a host name such as mail.example.org.", http.StatusBadRequest)
		return
	}
	if len(wanted) > maxCertRequest {
		http.Error(w, fmt.Sprintf("Request at most %d names at a time.", maxCertRequest), http.StatusBadRequest)
		return
	}
	hosts, err := m.hosts()
	if err != nil {
		http.Error(w, "The certificate requests could not be read", http.StatusInternalServerError)
		return
	}
	for _, host := range wanted {
		if len(host) > 253 || !certHost.MatchString(host) {
			http.Error(w, host+" isn't a host name such as mail.example.org.", http.StatusBadRequest)
			return
		}
		if why := s.reservedCertHost(m, host); why != "" {
			http.Error(w, why, http.StatusConflict)
			return
		}
		if m.uploaded(host) {
			http.Error(w, host+" already has an uploaded certificate. Remove it first.", http.StatusConflict)
			return
		}
		if slices.Contains(hosts, host) {
			http.Error(w, host+" is already requested.", http.StatusConflict)
			return
		}
	}
	if err = m.setHosts(append(hosts, wanted...)); err == nil {
		err = m.trigger()
	}
	if err != nil {
		slog.Error("certificate request failed", "hosts", wanted, "error", err)
		http.Error(w, "The certificate request could not be written", http.StatusInternalServerError)
		return
	}
	slog.Info("certificates requested", "actor", certActor(r), "hosts", wanted)
	names := strings.Join(wanted, ", ")
	writeJSON(w, map[string]string{"status": "Requested certificates for " + names + ". Each is issued only once its name points at this server."})
}

// handleTLSCertificateUpload stores an uploaded certificate and key for the
// host to install. The host is the certificate's first name; a wildcard
// *.example.org is filed as wildcard.example.org, a name it covers.
func (s *Server) handleTLSCertificateUpload(w http.ResponseWriter, r *http.Request) {
	m := certManagerFor(w)
	if m == nil {
		return
	}
	// decodeJSONBody's 64 KiB is ample: a chain and its key are a few.
	var in struct {
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
	}
	if !decodeJSONBody(w, r, &in) {
		return
	}
	pair, err := tls.X509KeyPair([]byte(in.Certificate), []byte(in.Key))
	if err != nil {
		http.Error(w, "The certificate and key don't form a pair: "+err.Error(), http.StatusBadRequest)
		return
	}
	leaf := pair.Leaf
	now := time.Now()
	switch {
	case leaf == nil || len(leaf.DNSNames) == 0:
		http.Error(w, "The certificate names no host (it has no DNS subject alternative names).", http.StatusBadRequest)
		return
	case now.After(leaf.NotAfter):
		http.Error(w, "The certificate has expired.", http.StatusBadRequest)
		return
	case now.Before(leaf.NotBefore):
		http.Error(w, "The certificate isn't valid yet.", http.StatusBadRequest)
		return
	}
	host := strings.ToLower(leaf.DNSNames[0])
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		host = "wildcard." + rest
	}
	if !certHost.MatchString(host) {
		http.Error(w, "The certificate's first name, "+leaf.DNSNames[0]+", isn't a host name this server can file it under.", http.StatusBadRequest)
		return
	}
	if why := s.reservedCertHost(m, host); why != "" {
		http.Error(w, why, http.StatusConflict)
		return
	}
	if hosts, _ := m.hosts(); slices.Contains(hosts, host) {
		http.Error(w, host+" has a Let's Encrypt certificate requested. Remove it first.", http.StatusConflict)
		return
	}
	if err = m.storeUpload(host, []byte(in.Certificate), []byte(in.Key)); err == nil {
		err = m.trigger()
	}
	if err != nil {
		slog.Error("certificate upload failed", "host", host, "error", err)
		http.Error(w, "The certificate could not be stored", http.StatusInternalServerError)
		return
	}
	slog.Info("certificate uploaded", "actor", certActor(r), "host", host, "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	writeJSON(w, map[string]string{"host": host, "status": "Uploaded the certificate for " + host + ". The mail services serve it within a minute. It isn't renewed automatically: upload a new one before " + leaf.NotAfter.UTC().Format("2 January 2006") + "."})
}

// storeUpload writes the pair under a temporary name and renames it into
// place, so the host sees the whole upload or none of it.
func (m *certManager) storeUpload(host string, cert, key []byte) error {
	root, err := m.uploadsRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tmp, err := os.MkdirTemp(m.uploads(), ".upload-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err = os.Chmod(tmp, 0o755); err != nil { // #nosec G302 -- read by the host's sync, another user
		return err
	}
	// The host's sync runs as another user and must read the key; the
	// directory above requests/ is private to the deployment's user.
	// #nosec G306 -- see above.
	if err = os.WriteFile(filepath.Join(tmp, "cert.pem"), cert, 0o644); err != nil {
		return err
	}
	// #nosec G306 -- see above.
	if err = os.WriteFile(filepath.Join(tmp, "key.pem"), key, 0o644); err != nil {
		return err
	}
	if err = root.RemoveAll(host); err != nil {
		return err
	}
	return root.Rename(filepath.Base(tmp), host)
}

// handleTLSCertificateDelete removes a requested or uploaded certificate;
// the host stops serving it on its next run, which this triggers.
func (s *Server) handleTLSCertificateDelete(w http.ResponseWriter, r *http.Request) {
	m := certManagerFor(w)
	if m == nil {
		return
	}
	host := strings.ToLower(mux.Vars(r)["host"])
	if !certHost.MatchString(host) {
		http.Error(w, "Not a host name.", http.StatusBadRequest)
		return
	}
	if why := s.reservedCertHost(m, host); why != "" {
		http.Error(w, why+" It can't be removed here.", http.StatusConflict)
		return
	}
	hosts, err := m.hosts()
	if err != nil {
		http.Error(w, "The certificate requests could not be read", http.StatusInternalServerError)
		return
	}
	removed := false
	if i := slices.Index(hosts, host); i >= 0 {
		if err = m.setHosts(slices.Delete(hosts, i, i+1)); err != nil {
			http.Error(w, "The certificate requests could not be written", http.StatusInternalServerError)
			return
		}
		removed = true
	}
	if m.uploaded(host) {
		if err = m.removeUpload(host); err != nil {
			http.Error(w, "The uploaded certificate could not be removed", http.StatusInternalServerError)
			return
		}
		removed = true
	}
	if !removed {
		http.Error(w, "No requested or uploaded certificate for "+host+".", http.StatusNotFound)
		return
	}
	if err = m.trigger(); err != nil {
		http.Error(w, "Removed, but the sync request could not be written; it applies at the next scheduled sync", http.StatusInternalServerError)
		return
	}
	slog.Info("certificate removed", "actor", certActor(r), "host", host)
	writeJSON(w, map[string]string{"status": "Removed " + host + ". The mail services stop serving it within a minute."})
}
