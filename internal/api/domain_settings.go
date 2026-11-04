package api

// A domain's settings dialog: its status and its DKIM keys. Anyone who
// administers the domain can read these; changing them stays with system
// administrators, like the rest of domain routing, because a wrong key or
// status changes what happens to all of the domain's mail.

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/gorilla/mux"
)

// dkimKeyView is one key as the dialog shows it. It has no private material:
// nothing in this API returns a private key once it is stored.
type dkimKeyView struct {
	Selector  string     `json:"selector"`
	Algorithm string     `json:"algorithm,omitempty"`
	Source    string     `json:"source"` // "console" or "configuration"
	Created   *time.Time `json:"created,omitempty"`
	Imported  bool       `json:"imported,omitempty"`
	Active    bool       `json:"active"`
	DNSName   string     `json:"dns_name"`
	Record    string     `json:"record,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// How a domain's mail is being signed.
const (
	signingOn           = "on"
	signingNoKey        = "no-key"        // nothing active
	signingOff          = "off"           // turned off for this domain
	signingPluginOff    = "plugin-off"    // the DKIM plugin is off for everyone
	signingConfigSource = "configuration" // the key came from elemta.toml
	signingStoreSource  = "console"       // the key was made or imported here
)

type domainSettingsView struct {
	Domain  string        `json:"domain"`
	Status  string        `json:"status"`
	Signing string        `json:"signing"`
	Keys    []dkimKeyView `json:"keys"`
}

// dkimStore is the key store beside the configuration this server edits.
func (s *Server) dkimStore() (dkim.Store, error) {
	if s.configPath == "" {
		return dkim.Store{}, fmt.Errorf("%w: this deployment has no configuration file to keep keys beside", provision.ErrUnavailable)
	}
	return dkim.StoreFor(s.configPath), nil
}

// configuredDomain normalises the path's domain and refuses one the server
// doesn't host, so a typo can't leave keys for a domain nobody can see.
func (s *Server) configuredDomain(ctx context.Context, r *http.Request) (string, error) {
	name, err := provision.DomainName(mux.Vars(r)["domain"])
	if err != nil {
		return "", err
	}
	domains, err := s.provisioner.Domains(ctx)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(domains, func(d provision.Domain) bool { return d.Name == name && d.Configured }) {
		return "", fmt.Errorf("%w: %s isn't a local domain", provision.ErrNotFound, name)
	}
	return name, nil
}

func (s *Server) configuredKey(domain string) (SigningDomainStatus, bool) {
	if s.mainConfig == nil || s.mainConfig.DKIM == nil {
		return SigningDomainStatus{}, false
	}
	for _, d := range s.mainConfig.DKIM.Domains {
		if d.Domain == domain {
			return d, true
		}
	}
	return SigningDomainStatus{}, false
}

func (s *Server) domainSettings(ctx context.Context, domain string) (domainSettingsView, error) {
	view := domainSettingsView{Domain: domain, Status: mailpolicy.DomainActive, Keys: []dkimKeyView{}}
	domains, err := s.provisioner.Domains(ctx)
	if err != nil {
		return view, err
	}
	for _, d := range domains {
		if d.Name == domain {
			view.Status = d.Status
		}
	}
	store, err := s.dkimStore()
	if err != nil {
		return view, err
	}
	state, err := store.Domain(domain)
	if err != nil {
		return view, err
	}
	dnsName := func(selector string) string { return dkim.RecordName(selector, domain) }
	for _, k := range state.Keys {
		created := k.Created
		view.Keys = append(view.Keys, dkimKeyView{
			Selector: k.Selector, Algorithm: k.Algorithm, Source: signingStoreSource, Created: &created,
			Imported: k.Imported, Active: !state.SigningOff && state.Active == k.Selector,
			DNSName: dnsName(k.Selector), Record: k.Record,
		})
	}
	plugin := s.mainConfig != nil && s.mainConfig.DKIM != nil
	configured, hasConfigured := s.configuredKey(domain)
	if hasConfigured {
		key := dkimKeyView{
			Selector: configured.Selector, Source: signingConfigSource, DNSName: dnsName(configured.Selector),
			Active: !state.SigningOff && state.Active == "" && plugin && s.mainConfig.DKIM.Sign,
		}
		key.Algorithm, err = dkim.LoadSigningKeyInfo(configured.PrivateKeyPath)
		if err == nil {
			var public crypto.PublicKey
			if public, err = dkim.LoadPublicKey(configured.PrivateKeyPath); err == nil {
				key.Record, err = dkim.DNSRecord(public)
			}
		}
		if err != nil {
			key.Error, key.Active = "This key can't be read by the admin service.", false
		}
		view.Keys = append(view.Keys, key)
	}
	switch {
	case plugin && !s.mainConfig.DKIM.Enabled:
		view.Signing = signingPluginOff
		for i := range view.Keys {
			view.Keys[i].Active = false
		}
	case state.SigningOff:
		view.Signing = signingOff
	case slices.ContainsFunc(view.Keys, func(k dkimKeyView) bool { return k.Active }):
		view.Signing = signingOn
	default:
		view.Signing = signingNoKey
	}
	return view, nil
}

// dkimChange runs one change to the store under the provisioning lock, which
// also covers configuration writes, then answers with the domain's settings.
func (s *Server) dkimChange(ctx context.Context, w http.ResponseWriter, r *http.Request, action, detail string, change func(dkim.Store, string) error) error {
	if err := scopeOf(r).systemOnly(); err != nil {
		return err
	}
	domain, err := s.configuredDomain(ctx, r)
	if err != nil {
		return err
	}
	store, err := s.dkimStore()
	if err != nil {
		return err
	}
	unlock, err := (provision.FileDomains{Path: s.configPath}).Lock(ctx)
	if err != nil {
		return err
	}
	err = change(store, domain)
	unlock()
	if err != nil {
		return err
	}
	s.provisionAudit(r, action, domain, detail)
	view, err := s.domainSettings(ctx, domain)
	if err != nil {
		return err
	}
	writeJSON(w, view)
	return nil
}

func (s *Server) domainSettingsRoutes(protected *mux.Router) {
	protected.HandleFunc("/domains/{domain}/settings", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		domain, err := s.configuredDomain(ctx, r)
		if err != nil {
			return err
		}
		if err := scopeOf(r).checkDomain(domain); err != nil {
			return err
		}
		view, err := s.domainSettings(ctx, domain)
		if err != nil {
			return err
		}
		writeJSON(w, view)
		return nil
	})).Methods("GET")
	// Read-only, so a domain's own administrators can run it too: they're the
	// ones who can change the domain's DNS.
	protected.HandleFunc("/domains/{domain}/dns-health", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		domain, err := s.configuredDomain(ctx, r)
		if err != nil {
			return err
		}
		if err := scopeOf(r).checkDomain(domain); err != nil {
			return err
		}
		view, err := s.domainSettings(ctx, domain)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, dnsHealthTimeout)
		defer cancel()
		writeJSON(w, s.runDNSHealth(ctx, view))
		return nil
	})).Methods("GET")
	protected.HandleFunc("/domains/{domain}/status", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := scopeOf(r).systemOnly(); err != nil {
			return err
		}
		var in struct {
			Status string `json:"status"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		domain := mux.Vars(r)["domain"]
		out, err := s.provisioner.SetDomainStatus(ctx, domain, in.Status)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "domain-status", out.Domain, out.Status)
		view, err := s.domainSettings(ctx, out.Domain)
		if err != nil {
			return err
		}
		writeJSON(w, view)
		return nil
	})).Methods("PUT")
	protected.HandleFunc("/domains/{domain}/dkim/keys", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		var in struct {
			Selector   string `json:"selector"`
			Algorithm  string `json:"algorithm"`
			PrivateKey string `json:"private_key"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		action := "dkim-generate"
		if in.PrivateKey != "" {
			action = "dkim-import"
		}
		return s.dkimChange(ctx, w, r, action, "selector "+in.Selector, func(store dkim.Store, domain string) error {
			if err := s.selectorFree(domain, in.Selector); err != nil {
				return err
			}
			var err error
			if in.PrivateKey != "" {
				_, err = store.Import(domain, in.Selector, in.PrivateKey)
			} else {
				_, err = store.Generate(domain, in.Selector, in.Algorithm)
			}
			return err
		})
	})).Methods("POST")
	protected.HandleFunc("/domains/{domain}/dkim/keys/{selector}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		selector := mux.Vars(r)["selector"]
		if r.Method == http.MethodDelete {
			return s.dkimChange(ctx, w, r, "dkim-delete", "selector "+selector, func(store dkim.Store, domain string) error {
				return store.Delete(domain, selector)
			})
		}
		var in struct {
			Selector string `json:"selector"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		return s.dkimChange(ctx, w, r, "dkim-rename", selector+" to "+in.Selector, func(store dkim.Store, domain string) error {
			if err := s.selectorFree(domain, in.Selector); err != nil {
				return err
			}
			return store.Rename(domain, selector, in.Selector)
		})
	})).Methods("PUT", "DELETE")
	protected.HandleFunc("/domains/{domain}/dkim/signing", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		// Selector names the stored key to sign with; empty means the
		// configuration file's. Enabled false stops signing, keeping keys.
		var in struct {
			Enabled  bool   `json:"enabled"`
			Selector string `json:"selector"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		action, detail := "dkim-activate", "selector "+in.Selector
		if !in.Enabled {
			action, detail = "dkim-signing-off", ""
		}
		return s.dkimChange(ctx, w, r, action, detail, func(store dkim.Store, domain string) error {
			if !in.Enabled {
				return store.SetSigning(domain, false)
			}
			return store.Activate(domain, in.Selector)
		})
	})).Methods("PUT")
	protected.HandleFunc("/domains/{domain}/dkim/keys/{selector}/dns", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		domain, err := s.configuredDomain(ctx, r)
		if err != nil {
			return err
		}
		if err := scopeOf(r).checkDomain(domain); err != nil {
			return err
		}
		view, err := s.domainSettings(ctx, domain)
		if err != nil {
			return err
		}
		selector := mux.Vars(r)["selector"]
		i := slices.IndexFunc(view.Keys, func(k dkimKeyView) bool { return k.Selector == selector })
		if i < 0 || view.Keys[i].Record == "" {
			return dkim.ErrNotFound
		}
		lookupTXT := net.DefaultResolver.LookupTXT
		if s.mailAuthLookupTXT != nil {
			lookupTXT = s.mailAuthLookupTXT
		}
		state, found, err := dkim.CheckDNS(ctx, lookupTXT, view.Keys[i].DNSName, view.Keys[i].Record)
		if err != nil {
			var failed *net.DNSError
			if errors.As(err, &failed) {
				return fmt.Errorf("%w: the DNS lookup failed: %s", dkim.ErrInvalid, failed.Err)
			}
			return err
		}
		writeJSON(w, map[string]string{"state": state, "found": found, "name": view.Keys[i].DNSName})
		return nil
	})).Methods("GET")
}

// dnsHealthTimeout bounds a check. Slow answers come back as "couldn't check"
// rather than holding the dialog open.
const dnsHealthTimeout = 12 * time.Second

func (s *Server) runDNSHealth(ctx context.Context, view domainSettingsView) dnshealth.Report {
	o := dnshealth.Options{Domain: view.Domain, Resolver: net.DefaultResolver, Signing: dnshealth.SigningNo}
	if s.mainConfig != nil {
		o.Hostname = s.mainConfig.Hostname
	}
	switch view.Signing {
	case signingOn:
		o.Signing = dnshealth.SigningOn
	case signingOff, signingPluginOff:
		o.Signing = dnshealth.SigningOff
	}
	for _, k := range view.Keys {
		if k.Active {
			o.DKIMKeys = append(o.DKIMKeys, dnshealth.DKIMKey{Name: k.DNSName, Record: k.Record})
		}
	}
	if s.dnsHealth != nil {
		return s.dnsHealth(ctx, o)
	}
	return dnshealth.Run(ctx, o)
}

// selectorFree refuses a selector the configuration file already uses for
// this domain: two keys can't share one DNS name.
func (s *Server) selectorFree(domain, selector string) error {
	if d, ok := s.configuredKey(domain); ok && d.Selector == selector {
		return dkim.ErrExists
	}
	return nil
}
