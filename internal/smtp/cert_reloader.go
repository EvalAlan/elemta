package smtp

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// certReloader serves a certificate from files on disk and picks up a renewed
// one without a restart.
//
// Certificates from certbot, a cert-manager sidecar or an operator copying
// files in are replaced on disk every couple of months. With the certificate
// loaded once into tls.Config.Certificates, the server kept presenting the old
// one until someone restarted it, and the usual way that was discovered was
// remote servers refusing an expired certificate.
//
// The files are checked at most once per checkInterval, from the handshake
// path, so an idle server does no work and a busy one stats two files every
// half minute. A pair that fails to load (a renewal caught half-written, a key
// that does not match) is logged and the previous certificate stays in use;
// the next check tries again.
type certReloader struct {
	certFile, keyFile string
	checkInterval     time.Duration
	onReload          func(tls.Certificate) // optional; called after a successful reload
	logf              func(format string, args ...interface{})

	mu          sync.Mutex
	cert        *tls.Certificate
	certMod     time.Time
	keyMod      time.Time
	lastChecked time.Time
	now         func() time.Time
}

const defaultCertCheckInterval = 30 * time.Second

// newCertReloader loads the pair once, failing if it cannot: a server that
// starts without its certificate should say so at startup.
func newCertReloader(certFile, keyFile string, logf func(string, ...interface{})) (*certReloader, error) {
	r := &certReloader{
		certFile:      certFile,
		keyFile:       keyFile,
		checkInterval: defaultCertCheckInterval,
		logf:          logf,
		now:           time.Now,
	}
	if r.logf == nil {
		r.logf = func(string, ...interface{}) {}
	}
	certMod, keyMod, err := r.modTimes()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	r.cert, r.certMod, r.keyMod, r.lastChecked = &cert, certMod, keyMod, r.now()
	return r, nil
}

func (r *certReloader) modTimes() (time.Time, time.Time, error) {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to read TLS certificate: %w", err)
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to read TLS key: %w", err)
	}
	return ci.ModTime(), ki.ModTime(), nil
}

// Current returns the certificate in use.
func (r *certReloader) Current() tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.cert
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.maybeReload()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert, nil
}

// maybeReload re-reads the pair if the check interval has passed and either
// file's modification time changed.
func (r *certReloader) maybeReload() {
	r.mu.Lock()
	now := r.now()
	if now.Sub(r.lastChecked) < r.checkInterval {
		r.mu.Unlock()
		return
	}
	r.lastChecked = now
	prevCert, prevKey := r.certMod, r.keyMod
	r.mu.Unlock()

	certMod, keyMod, err := r.modTimes()
	if err != nil {
		r.logf("TLS certificate check failed, keeping the current certificate: %v", err)
		return
	}
	if certMod.Equal(prevCert) && keyMod.Equal(prevKey) {
		return
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		r.logf("TLS certificate changed on disk but did not load, keeping the current certificate: %v", err)
		return
	}

	r.mu.Lock()
	r.cert, r.certMod, r.keyMod = &cert, certMod, keyMod
	r.mu.Unlock()
	r.logf("Reloaded TLS certificate from %s", r.certFile)
	if r.onReload != nil {
		r.onReload(cert)
	}
}
