package api

// The admin console's view of abuse protection (internal/abuse). The policy is
// saved to the configuration file, which is what makes it outlast Valkey, and
// published to every service.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/gorilla/mux"
)

// SetAbuse connects the shared engine.
func (s *Server) SetAbuse(e *abuse.Engine) {
	s.abuse = e
	if s.authMiddleware != nil {
		s.authMiddleware.abuse = e
	}
}

func (s *Server) abuseRoutes(api *mux.Router) {
	if s.authMiddleware == nil {
		return
	}
	configure := s.authMiddleware.RequirePermission(auth.PermissionSystemConfig)
	api.Handle("/abuse", configure(http.HandlerFunc(s.handleAbuseStatus))).Methods("GET")
	api.Handle("/abuse/policy", configure(http.HandlerFunc(s.handleAbusePolicy))).Methods("PUT")
}

func (s *Server) handleAbuseStatus(w http.ResponseWriter, r *http.Request) {
	if s.abuse == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	writeJSON(w, map[string]any{"policy": s.abuse.Policy(), "shared": s.abuse.Shared(ctx)})
}

func (s *Server) handleAbusePolicy(w http.ResponseWriter, r *http.Request) {
	if s.abuse == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	// Over the policy in force, so a field left out keeps its value while one
	// sent as zero is still refused below.
	p := s.abuse.Policy()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Send the policy as JSON", http.StatusBadRequest)
		return
	}
	entries := make([]string, 0, len(p.Allowlist))
	for _, entry := range p.Allowlist {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	p.Allowlist = entries
	if err := p.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.mainConfig != nil && s.configPath != "" {
		previous := s.mainConfig.Abuse
		s.mainConfig.Abuse = &p
		if err := s.persistConfig(); err != nil {
			s.mainConfig.Abuse = previous
			slog.Error("Failed to save the abuse policy", "error", err)
			http.Error(w, "Failed to save the policy", http.StatusInternalServerError)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	published := s.abuse.Publish(ctx, p) == nil
	slog.Info("Abuse policy changed", "mode", p.Mode, "connections_per_address", p.ConnectionsPerAddress, "allowlist", len(p.Allowlist), "published", published)
	writeJSON(w, map[string]any{"policy": p, "shared": s.abuse.Shared(ctx), "published": published})
}
