package mailbox

// Certificates are reloaded from disk when they change, so a renewed
// certificate (ACME, cert-manager) takes effect without a restart and
// without dropping connections. The files are checked at most once a
// minute, on handshakes.

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.cert, r.modTime, r.checked = &cert, st.ModTime(), time.Now()
	return nil
}

func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) > time.Minute {
		r.checked = time.Now()
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.modTime) {
			// A half-written renewal fails to load; keep serving the old
			// certificate and try again later.
			_ = r.load()
		}
	}
	return r.cert, nil
}
