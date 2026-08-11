package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"

	"github.com/busybox42/elemta/internal/dkim"
	"github.com/gorilla/mux"
)

// publishedRSAKey extracts the RSA public key from a DKIM TXT record.
//
// This parses the record the verifier itself reads rather than delegating to a
// second DKIM implementation. A preflight that consults a different library
// than the one verifying live mail can report a healthy setup that does not
// actually work, which is worse than no preflight at all.
func publishedRSAKey(records []string) (*rsa.PublicKey, error) {
	for _, record := range records {
		tags := map[string]string{}
		for _, part := range strings.Split(record, ";") {
			name, value, found := strings.Cut(part, "=")
			if !found {
				continue
			}
			tags[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
		// k defaults to rsa when absent (RFC 6376 §3.6.1). An ed25519 record is
		// valid but cannot be compared against an RSA signing key, so say that
		// rather than reporting a mismatch.
		if k, ok := tags["k"]; ok && !strings.EqualFold(k, "rsa") {
			return nil, fmt.Errorf("published key uses %s; this check only understands rsa", k)
		}
		encoded := tags["p"]
		if encoded == "" {
			continue
		}
		// Whitespace is permitted anywhere inside the base64 value.
		encoded = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, encoded)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("published key is not valid base64")
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("published key is not a valid public key")
		}
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("published key is not an RSA key")
		}
		return rsaKey, nil
	}
	return nil, fmt.Errorf("no published key found in the TXT record")
}

// handleCheckMailAuthPlugin performs an operator-requested DNS/key preflight.
// It never returns private key material; only whether the configured file can
// be securely loaded and the public TXT records DNS currently serves.
func (s *Server) handleCheckMailAuthPlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := mux.Vars(r)["plugin"]
	var request struct {
		Domain string `json:"domain"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&request)
	}
	domain := strings.ToLower(strings.TrimSpace(request.Domain))
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	response := map[string]interface{}{"plugin": pluginName, "domain": domain}
	lookupTXT := net.DefaultResolver.LookupTXT
	if s.mailAuthLookupTXT != nil {
		lookupTXT = s.mailAuthLookupTXT
	}
	var matched []string
	lookup := func(name, prefix string) error {
		response["dns_name"] = name
		records, err := lookupTXT(ctx, name)
		if err != nil {
			return err
		}
		matching := make([]string, 0, len(records))
		for _, record := range records {
			if prefix == "" || strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), prefix) {
				matching = append(matching, record)
			}
		}
		response["records"] = matching
		response["published"] = len(matching) > 0
		matched = matching
		if len(matching) == 0 {
			return fmt.Errorf("no matching TXT record is published at %s", name)
		}
		return nil
	}

	var err error
	switch pluginName {
	case "spf":
		if domain == "" {
			err = fmt.Errorf("domain is required")
		} else {
			err = lookup(domain, "v=spf1")
		}
	case "dmarc":
		if domain == "" {
			err = fmt.Errorf("domain is required")
		} else {
			err = lookup("_dmarc."+domain, "v=dmarc1")
		}
	case "dkim":
		if s.mainConfig == nil || s.mainConfig.DKIM == nil || len(s.mainConfig.DKIM.Domains) == 0 {
			err = fmt.Errorf("no DKIM signing domains are configured")
			break
		}
		selected := s.mainConfig.DKIM.Domains[0]
		if domain != "" {
			found := false
			for _, candidate := range s.mainConfig.DKIM.Domains {
				if strings.EqualFold(candidate.Domain, domain) {
					selected, found = candidate, true
					break
				}
			}
			if !found {
				err = fmt.Errorf("domain %q has no configured DKIM key", domain)
				break
			}
		}
		domain = selected.Domain
		response["domain"] = domain
		response["selector"] = selected.Selector
		privateKey, loadErr := dkim.LoadRSAPrivateKey(selected.PrivateKeyPath)
		if loadErr != nil {
			err = fmt.Errorf("private key: %w", loadErr)
			break
		}
		response["key_loaded"] = true
		err = lookup(selected.Selector+"._domainkey."+selected.Domain, "v=dkim1")
		if err == nil {
			publishedKey, parseErr := publishedRSAKey(matched)
			if parseErr != nil {
				err = fmt.Errorf("published DKIM key: %w", parseErr)
			} else if !privateKey.PublicKey.Equal(publishedKey) {
				err = fmt.Errorf("published DKIM key does not match the configured private key")
			} else {
				response["key_matches_dns"] = true
			}
		}
	default:
		http.Error(w, "mail-auth plugin not found", http.StatusNotFound)
		return
	}
	if err != nil {
		response["ok"] = false
		response["error"] = err.Error()
		writeJSONStatus(w, http.StatusUnprocessableEntity, response)
		return
	}
	response["ok"] = true
	writeJSON(w, response)
}

func writeJSONStatus(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
