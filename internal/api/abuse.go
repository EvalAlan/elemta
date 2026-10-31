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
	api.Handle("/abuse/metrics", configure(http.HandlerFunc(s.handleAbuseMetrics))).Methods("GET")
	api.Handle("/abuse/policy", configure(http.HandlerFunc(s.handleAbusePolicy))).Methods("PUT")
	api.Handle("/abuse/blocks", configure(http.HandlerFunc(s.handleAbuseBlock))).Methods("POST")
	api.Handle("/abuse/blocks", configure(http.HandlerFunc(s.handleAbuseUnblock))).Methods("DELETE")
}

func (s *Server) handleAbuseStatus(w http.ResponseWriter, r *http.Request) {
	if s.abuse == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	addr := s.loginAddr(r)
	writeJSON(w, map[string]any{
		"policy": s.abuse.Policy(), "shared": s.abuse.Shared(ctx),
		"blocks": s.abuse.Blocks(), "events": s.abuse.Events(ctx), "accounts": s.abuse.Accounts(ctx),
		"enforcers": s.abuse.Enforcers(ctx),
		// So the page can warn an administrator who could block themselves.
		"you": addr, "you_exempt": s.abuse.Exempt(addr),
	})
}

func (s *Server) handleAbuseMetrics(w http.ResponseWriter, r *http.Request) {
	if s.abuse == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, s.abuse.Stats(ctx, r.URL.Query().Get("range")))
}

func abuseActor(r *http.Request) string {
	if ac := GetAuthContext(r); ac != nil {
		return ac.Username
	}
	return "unknown"
}

func (s *Server) handleAbuseBlock(w http.ResponseWriter, r *http.Request) {
	if s.abuse == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Address string `json:"address"`
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "Send the address as JSON", http.StatusBadRequest)
		return
	}
	if in.Minutes < 1 || in.Minutes > 43200 {
		http.Error(w, "A block must last between 1 minute and 30 days", http.StatusBadRequest)
		return
	}
	if len(in.Reason) > 200 {
		http.Error(w, "Keep the reason under 200 characters", http.StatusBadRequest)
		return
	}
	// The check the allowlist can't make: an administrator not on it could
	// otherwise cut off the address they're working from.
	if abuse.Network(in.Address) != "" && abuse.Network(in.Address) == abuse.Network(s.loginAddr(r)) {
		http.Error(w, "That is the address you are using", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	block, err := s.abuse.BlockAddress(ctx, in.Address, in.Reason, abuseActor(r), time.Duration(in.Minutes)*time.Minute)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("Address blocked by an administrator", "address", block.Network, "by", abuseActor(r))
	writeJSON(w, block)
}

func (s *Server) handleAbuseUnblock(w http.ResponseWriter, r *http.Request) {
	if s.abuse == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	address := r.URL.Query().Get("address")
	if err := s.abuse.Unblock(ctx, address, abuseActor(r)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("Address unblocked", "address", abuse.Network(address), "by", abuseActor(r))
	writeJSON(w, map[string]bool{"ok": true})
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
		slog.Info("Saving the abuse policy", "by", abuseActor(r))
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
