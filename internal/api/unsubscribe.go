package api

import (
	"crypto/rand"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/EvalAlan/elemta/internal/campaign"
	"github.com/EvalAlan/elemta/internal/suppression"
	"github.com/gorilla/mux"
)

// One-click unsubscribe links for Mass Mailer campaigns (campaign/unsubscribe.go).
//
// /unsubscribe/<token> is the one page of the admin console the public
// reaches: Caddy routes that path alone from the mail host to it
// (deployments/cloud/Caddyfile). It needs no sign-in, because the recipient
// and their mail provider have none; the token's signature is what makes it
// safe. A POST unsubscribes, which is what mail providers send (RFC 8058).
// A GET only shows a button that POSTs: link checkers and previewers fetch
// links in mail, and a GET that unsubscribed would remove people who never
// asked.

var (
	unsubscribeOnce sync.Once
	unsubscribeKey  []byte
)

// unsubscriber signs links with a key kept beside the runtime configuration,
// made on first use, so links in mail already sent keep working across
// restarts. Without a configuration file the key lasts until the process
// ends, which is enough for a test stack.
func (s *Server) unsubscriber() *campaign.Unsubscriber {
	unsubscribeOnce.Do(func() {
		unsubscribeKey = s.loadUnsubscribeKey()
	})
	host := s.massMailerHostname()
	base := ""
	if host != "" && host != "localhost" && strings.Contains(host, ".") {
		base = "https://" + host + "/unsubscribe/"
	}
	return campaign.NewUnsubscriber(unsubscribeKey, base)
}

func (s *Server) loadUnsubscribeKey() []byte {
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil
	}
	if s.configPath == "" {
		return fresh
	}
	path := filepath.Join(filepath.Dir(s.configPath), "unsubscribe.key")
	// #nosec G304 -- a fixed name beside the operator's configuration file
	if key, err := os.ReadFile(path); err == nil && len(key) >= 32 {
		return key
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("Could not read the unsubscribe key; links in mail sent before now won't work", "error", err)
		return fresh
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- as above
	if err != nil {
		// Another admin made it first: use theirs.
		// #nosec G304 -- as above
		if key, rerr := os.ReadFile(path); rerr == nil && len(key) >= 32 {
			return key
		}
		slog.Warn("Could not save the unsubscribe key; links will stop working on restart", "error", err)
		return fresh
	}
	_, werr := f.Write(fresh)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		slog.Warn("Could not save the unsubscribe key; links will stop working on restart", "error", werr)
	}
	return fresh
}

var unsubscribePage = template.Must(template.New("unsubscribe").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Unsubscribe</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#0E1726;background:#F4F6F8}
button{font:inherit;padding:.6rem 1.2rem;border:0;border-radius:6px;background:#0B6E66;color:#fff;cursor:pointer}</style>
</head><body>
{{if .Done}}<h1>You're unsubscribed</h1><p>{{.Address}} won't get these mailings again.</p>
{{else if .Invalid}}<h1>This link doesn't work</h1><p>It may have been cut short by your mail app. Try the unsubscribe option your mail app shows for the message instead.</p>
{{else if .Unavailable}}<h1>Try again later</h1><p>The unsubscribe list can't be reached right now.</p>
{{else}}<h1>Unsubscribe</h1><p>Stop sending these mailings to {{.Address}}?</p>
<form method="post"><input type="hidden" name="List-Unsubscribe" value="One-Click"><button type="submit">Unsubscribe</button></form>{{end}}
</body></html>`))

type unsubscribeView struct {
	Address                    string
	Done, Invalid, Unavailable bool
}

func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	campaignID, address, ok := s.unsubscriber().Parse(mux.Vars(r)["token"])
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = unsubscribePage.Execute(w, unsubscribeView{Invalid: true})
		return
	}
	view := unsubscribeView{Address: address}
	if r.Method == http.MethodPost {
		if s.suppressed == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = unsubscribePage.Execute(w, unsubscribeView{Unavailable: true})
			return
		}
		reason := "Used the unsubscribe link in campaign " + campaignID
		if err := s.suppressed.Add(r.Context(), suppression.Entry{Address: address, Source: suppression.SourceUnsubscribe, Reason: reason}); err != nil {
			slog.Error("Unsubscribe failed", "campaign", campaignID, "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = unsubscribePage.Execute(w, unsubscribeView{Unavailable: true})
			return
		}
		slog.Info("Unsubscribed", "component", "mass-mailer", "campaign", campaignID, "address", address)
		view.Done = true
	}
	_ = unsubscribePage.Execute(w, view)
}
