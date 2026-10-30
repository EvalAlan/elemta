// Package tlssni picks a server certificate by the name a client asked for.
//
// One server can be the mail host for several domains (mail.example.org,
// mail.example.net), and a mail app checks that the certificate names the
// host it dialled. A single certificate can't name them all when an ACME
// client like Caddy issues one certificate per name, so the extra ones are
// kept in a directory, one subdirectory per certificate:
//
//	<dir>/mail.example.net/cert.pem
//	<dir>/mail.example.net/key.pem
//
// The subdirectory's name is only a label; the certificate's own names
// decide which handshakes it serves. A handshake that names none of them,
// or names no host at all, gets the server's primary certificate, so adding
// the directory changes nothing for existing clients.
//
// The directory is rescanned at most once per interval from the handshake
// path, so a renewal or a newly added domain is picked up without a restart.
// A pair that fails to load (a renewal caught half-written) keeps the
// previously loaded certificate for that subdirectory.
package tlssni

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultInterval = 30 * time.Second

// Dir serves the certificates found under one directory.
type Dir struct {
	dir      string
	interval time.Duration
	logf     func(format string, args ...any)
	now      func() time.Time

	mu      sync.Mutex
	certs   map[string]*entry
	scanned time.Time
}

type entry struct {
	cert              *tls.Certificate
	certMod, keyMod   time.Time
	certPath, keyPath string
}

// New loads every pair under dir. A missing directory is not an error: it
// is created by whatever adds the first extra domain, and picked up then.
func New(dir string, logf func(string, ...any)) *Dir {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	d := &Dir{dir: dir, interval: defaultInterval, logf: logf, now: time.Now, certs: map[string]*entry{}}
	d.scan()
	return d
}

// Lookup returns the certificate that names serverName, or nil when none
// does and the caller should use its primary certificate.
func (d *Dir) Lookup(serverName string) *tls.Certificate {
	name := strings.TrimSuffix(strings.ToLower(serverName), ".")
	if name == "" {
		return nil
	}
	d.mu.Lock()
	if d.now().Sub(d.scanned) >= d.interval {
		d.mu.Unlock()
		d.scan()
		d.mu.Lock()
	}
	defer d.mu.Unlock()
	for _, e := range d.certs {
		if e.cert.Leaf != nil && e.cert.Leaf.VerifyHostname(name) == nil {
			return e.cert
		}
	}
	return nil
}

// Wrap returns a GetCertificate function that tries the directory first and
// falls back to primary.
func (d *Dir) Wrap(primary func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := d.Lookup(hello.ServerName); c != nil {
			return c, nil
		}
		return primary(hello)
	}
}

func (d *Dir) scan() {
	d.mu.Lock()
	d.scanned = d.now()
	old := d.certs
	d.mu.Unlock()

	entries, err := os.ReadDir(d.dir)
	if err != nil && !os.IsNotExist(err) {
		d.logf("TLS certificate directory %s unreadable, keeping the loaded certificates: %v", d.dir, err)
		return
	}
	next := make(map[string]*entry, len(entries))
	for _, de := range entries {
		if !de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		name := de.Name()
		e := &entry{certPath: filepath.Join(d.dir, name, "cert.pem"), keyPath: filepath.Join(d.dir, name, "key.pem")}
		ci, err1 := os.Stat(e.certPath)
		ki, err2 := os.Stat(e.keyPath)
		if err1 != nil || err2 != nil {
			continue
		}
		e.certMod, e.keyMod = ci.ModTime(), ki.ModTime()
		if prev := old[name]; prev != nil && prev.certMod.Equal(e.certMod) && prev.keyMod.Equal(e.keyMod) {
			next[name] = prev
			continue
		}
		cert, err := tls.LoadX509KeyPair(e.certPath, e.keyPath)
		if err != nil {
			if prev := old[name]; prev != nil {
				d.logf("TLS certificate %s changed but did not load, keeping the previous one: %v", e.certPath, err)
				next[name] = prev
			} else {
				d.logf("TLS certificate %s did not load: %v", e.certPath, err)
			}
			continue
		}
		e.cert = &cert
		next[name] = e
		d.logf("Loaded TLS certificate %s", e.certPath)
	}

	d.mu.Lock()
	d.certs = next
	d.mu.Unlock()
}
