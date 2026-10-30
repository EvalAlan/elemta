package dkim

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Keys managed from the admin console.
//
// [plugins.dkim] domains belong to whoever writes the configuration, and a
// deploy that reseeds the runtime configuration replaces them. A key made in
// the console must outlive that, and must not be pasted into a config file by
// hand, so these live in a sidecar directory beside the configuration:
// <config>.dkim/keys.json for what is known about each key, and
// <config>.dkim/<domain>/<selector>.key for the key itself. Reseeding removes
// only the configuration file. It is a sidecar for the same reason the
// provisioning lock and generation are: the console and the SMTP server are
// separate processes whose one shared thing is the runtime configuration
// volume.
//
// A generated key does not sign anything until it is activated, because its
// public half has to be in DNS first. Signing with a key receivers can't find
// fails DKIM for every message, and under DMARC p=reject that loses mail.

// Algorithms a key can be generated with.
const (
	AlgorithmRSA     = "rsa-2048"
	AlgorithmEd25519 = "ed25519"
)

// ErrInvalid is a request the store refuses; the message explains why.
var ErrInvalid = errors.New("invalid")

// ErrNotFound is a domain or selector the store has no key for.
var ErrNotFound = errors.New("no such key")

// ErrExists is a selector already in use for the domain.
var ErrExists = errors.New("that selector already exists for this domain")

// selectorRE is one DNS label, which is all a selector needs here and keeps
// it safe as a file name.
var selectorRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// StoredKey describes a key. The private half is never part of it.
type StoredKey struct {
	Selector  string    `json:"selector"`
	Algorithm string    `json:"algorithm"`
	Created   time.Time `json:"created"`
	// Imported is an existing key brought in rather than generated here.
	Imported bool `json:"imported,omitempty"`
	// Record is the TXT value to publish at <selector>._domainkey.<domain>.
	Record string `json:"record"`
}

// DomainKeys is what the store holds for a domain.
type DomainKeys struct {
	// Active is the selector signing this domain's mail, or empty.
	Active string `json:"active,omitempty"`
	// SigningOff stops signing for the domain altogether, including with a
	// key from the configuration file.
	SigningOff bool        `json:"signing_off,omitempty"`
	Keys       []StoredKey `json:"keys,omitempty"`
}

// Key returns the key with this selector.
func (d DomainKeys) Key(selector string) (StoredKey, bool) {
	for _, k := range d.Keys {
		if k.Selector == selector {
			return k, true
		}
	}
	return StoredKey{}, false
}

// Store is the sidecar directory. It doesn't lock: the admin API serialises
// writers with the provisioning lock, and readers see keys.json replaced by
// a rename.
type Store struct{ Dir string }

// StoreFor names the store that belongs to a configuration file.
func StoreFor(configPath string) Store { return Store{Dir: configPath + ".dkim"} }

// ManifestPath is the file whose change means signing should be rebuilt.
func (s Store) ManifestPath() string { return filepath.Join(s.Dir, "keys.json") }

// keyPath stays inside the store whatever it is given. Callers validate
// selectors and domains too, but private keys shouldn't depend on all of them
// remembering: cleaning from a leading slash leaves no ".." to climb out with.
func (s Store) keyPath(domain, selector string) string {
	return filepath.Join(s.Dir, filepath.Clean("/"+domain), filepath.Clean("/"+selector)+".key")
}

func (s Store) load() (map[string]DomainKeys, error) {
	// #nosec G304 -- beside the operator's configuration, not request-derived
	data, err := os.ReadFile(s.ManifestPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]DomainKeys{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]DomainKeys{}
	if err = json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.ManifestPath(), err)
	}
	return out, nil
}

func (s Store) save(all map[string]DomainKeys) error {
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.ManifestPath(), data)
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dkim-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Domain returns what the store holds for a domain.
func (s Store) Domain(domain string) (DomainKeys, error) {
	all, err := s.load()
	if err != nil {
		return DomainKeys{}, err
	}
	return all[domain], nil
}

// Generate makes a new key and stores it, inactive.
func (s Store) Generate(domain, selector, algorithm string) (StoredKey, error) {
	keyType := ""
	switch algorithm {
	case "", AlgorithmRSA:
		algorithm, keyType = AlgorithmRSA, "rsa"
	case AlgorithmEd25519:
		keyType = "ed25519"
	default:
		return StoredKey{}, fmt.Errorf("%w: unknown algorithm %q", ErrInvalid, algorithm)
	}
	signer, err := GenerateKey(keyType, 0)
	if err != nil {
		return StoredKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return StoredKey{}, err
	}
	return s.add(domain, selector, signer, algorithm, false, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// Import stores an existing PEM private key, inactive.
func (s Store) Import(domain, selector, privateKeyPEM string) (StoredKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return StoredKey{}, fmt.Errorf("%w: that isn't a PEM private key", ErrInvalid)
	}
	signer, _, err := parsePrivateKeyBlock(block)
	if err != nil {
		return StoredKey{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	algorithm := AlgorithmEd25519
	if key, ok := signer.(*rsa.PrivateKey); ok {
		if key.N.BitLen() < 1024 {
			return StoredKey{}, fmt.Errorf("%w: receivers ignore RSA keys under 1024 bits", ErrInvalid)
		}
		algorithm = fmt.Sprintf("rsa-%d", key.N.BitLen())
	}
	return s.add(domain, selector, signer, algorithm, true, pem.EncodeToMemory(block))
}

func (s Store) add(domain, selector string, signer crypto.Signer, algorithm string, imported bool, keyPEM []byte) (StoredKey, error) {
	if !selectorRE.MatchString(selector) {
		return StoredKey{}, fmt.Errorf("%w: a selector is lowercase letters, digits and inner hyphens", ErrInvalid)
	}
	if strings.ContainsAny(domain, "/\\") || domain == "" || strings.HasPrefix(domain, ".") {
		return StoredKey{}, fmt.Errorf("%w: enter a domain name", ErrInvalid)
	}
	all, err := s.load()
	if err != nil {
		return StoredKey{}, err
	}
	state := all[domain]
	if _, taken := state.Key(selector); taken {
		return StoredKey{}, ErrExists
	}
	record, err := DNSRecord(signer.Public())
	if err != nil {
		return StoredKey{}, err
	}
	path := s.keyPath(domain, selector)
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return StoredKey{}, err
	}
	// The temporary file is 0600 from CreateTemp, which is what the signer
	// insists on.
	if err = writeFileAtomic(path, keyPEM); err != nil {
		return StoredKey{}, err
	}
	key := StoredKey{Selector: selector, Algorithm: algorithm, Created: time.Now().UTC(), Imported: imported, Record: record}
	state.Keys = append(state.Keys, key)
	sort.Slice(state.Keys, func(i, j int) bool { return state.Keys[i].Selector < state.Keys[j].Selector })
	all[domain] = state
	return key, s.save(all)
}

// Activate signs the domain's mail with a stored key from now on. An empty
// selector goes back to the configuration file's key, if it has one.
func (s Store) Activate(domain, selector string) error {
	return s.update(domain, func(state *DomainKeys) error {
		if selector != "" {
			if _, ok := state.Key(selector); !ok {
				return ErrNotFound
			}
			if _, err := LoadSigningKeyInfo(s.keyPath(domain, selector)); err != nil {
				return err
			}
		}
		state.Active, state.SigningOff = selector, false
		return nil
	})
}

// SetSigning turns signing for the domain off or back on, keeping its keys.
func (s Store) SetSigning(domain string, on bool) error {
	return s.update(domain, func(state *DomainKeys) error {
		state.SigningOff = !on
		return nil
	})
}

// Rename changes the selector of a key that isn't signing. The selector is
// part of where the public key is published, so renaming one in use would
// break every signature until DNS caught up.
func (s Store) Rename(domain, selector, next string) error {
	if !selectorRE.MatchString(next) {
		return fmt.Errorf("%w: a selector is lowercase letters, digits and inner hyphens", ErrInvalid)
	}
	return s.update(domain, func(state *DomainKeys) error {
		i := -1
		for n, k := range state.Keys {
			if k.Selector == selector {
				i = n
			}
			if k.Selector == next {
				return ErrExists
			}
		}
		if i < 0 {
			return ErrNotFound
		}
		if state.Active == selector {
			return fmt.Errorf("%w: activate another key before renaming this one", ErrInvalid)
		}
		if err := os.Rename(s.keyPath(domain, selector), s.keyPath(domain, next)); err != nil {
			return err
		}
		state.Keys[i].Selector = next
		return nil
	})
}

// Delete removes a key that isn't signing, private half included.
func (s Store) Delete(domain, selector string) error {
	return s.update(domain, func(state *DomainKeys) error {
		if _, ok := state.Key(selector); !ok {
			return ErrNotFound
		}
		if state.Active == selector {
			return fmt.Errorf("%w: activate another key before deleting this one", ErrInvalid)
		}
		keys := state.Keys[:0]
		for _, k := range state.Keys {
			if k.Selector != selector {
				keys = append(keys, k)
			}
		}
		state.Keys = keys
		return os.Remove(s.keyPath(domain, selector))
	})
}

func (s Store) update(domain string, change func(*DomainKeys) error) error {
	all, err := s.load()
	if err != nil {
		return err
	}
	state := all[domain]
	if err = change(&state); err != nil {
		return err
	}
	all[domain] = state
	return s.save(all)
}

// Apply lays the store over the configuration's signing domains and returns
// the signing configuration to use. A stored key replaces the configuration's
// for its domain. cfg may be nil, which is how [plugins.dkim] sign = false
// arrives: activating a key is itself the decision to sign that domain, and
// otherwise the first key could never be used, since the configuration refuses
// sign = true without a domain listed. Pass enabled false when the plugin is
// switched off altogether, which outranks everything here.
//
// A store that can't be read, or an active key that can't be loaded, is logged
// and skipped: the signer refuses to start on a bad key, and a damaged sidecar
// must not stop the server taking mail.
func (s Store) Apply(cfg *Config, enabled bool, logger *slog.Logger) *Config {
	if !enabled {
		return cfg
	}
	if logger == nil {
		logger = slog.Default()
	}
	all, err := s.load()
	if err != nil {
		logger.Error("DKIM key store unreadable; using the configured keys only", "error", err)
		return cfg
	}
	if len(all) == 0 {
		return cfg
	}
	out := &Config{Enabled: true}
	if cfg != nil {
		next := *cfg
		next.Domains = nil
		out = &next
		for _, d := range cfg.Domains {
			if state, ok := all[strings.ToLower(d.Domain)]; ok && state.SigningOff {
				continue
			}
			if !s.overrides(strings.ToLower(d.Domain), all, logger) {
				out.Domains = append(out.Domains, d)
			}
		}
	}
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, domain := range names {
		if s.overrides(domain, all, logger) {
			out.Domains = append(out.Domains, DomainConfig{Domain: domain, Selector: all[domain].Active, PrivateKeyPath: s.keyPath(domain, all[domain].Active)})
		}
	}
	if len(out.Domains) == 0 {
		return nil
	}
	return out
}

// overrides reports whether the domain signs with a usable stored key.
func (s Store) overrides(domain string, all map[string]DomainKeys, logger *slog.Logger) bool {
	state := all[domain]
	if state.SigningOff || state.Active == "" {
		return false
	}
	if _, err := LoadSigningKeyInfo(s.keyPath(domain, state.Active)); err != nil {
		logger.Error("Active DKIM key unusable; not signing with it", "domain", domain, "selector", state.Active, "error", err)
		return false
	}
	return true
}

// DNSState says whether a key's record is published.
const (
	DNSMatch    = "match"    // published, and it is this key
	DNSMissing  = "missing"  // no DKIM record at that name
	DNSMismatch = "mismatch" // a record is there, for a different key
)

// CheckDNS compares what DNS publishes for a key with its record, and returns
// the state and what was found.
func CheckDNS(ctx context.Context, lookupTXT func(context.Context, string) ([]string, error), name, record string) (string, string, error) {
	values, err := lookupTXT(ctx, name)
	if err != nil {
		var failed *net.DNSError
		if errors.As(err, &failed) && failed.IsNotFound {
			return DNSMissing, "", nil
		}
		return "", "", err
	}
	want, err := PublishedKey([]string{record})
	if err != nil {
		return "", "", err
	}
	found := ""
	for _, v := range values {
		published, err := PublishedKey([]string{v})
		if err != nil {
			continue
		}
		if SamePublicKey(want, published) {
			return DNSMatch, v, nil
		}
		found = v
	}
	if found != "" {
		return DNSMismatch, found, nil
	}
	return DNSMissing, "", nil
}
