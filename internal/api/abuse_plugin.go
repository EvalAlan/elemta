package api

// Abuse protection as a plugin. Its settings have their own API (abuse.go);
// this is the switch.

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
)

func (s *Server) setAbusePlugin(w http.ResponseWriter, r *http.Request, enabled bool) {
	if s.abuse == nil || s.authMiddleware == nil {
		http.Error(w, "Abuse protection is not available", http.StatusServiceUnavailable)
		return
	}
	p := s.abuse.Policy()
	switch {
	case !enabled:
		p.Mode = abuse.ModeOff
	case p.Mode == abuse.ModeOff:
		p.Mode = abuse.ModeEnforce
		// Deny rules do nothing while it's off, so switching it on is where
		// one could end this very session.
		if rule, cut := rulesCutOff(p, s.loginAddr(r)); cut {
			http.Error(w, "A saved rule would block the address you are using: "+rule.Value, http.StatusBadRequest)
			return
		}
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
	slog.Info("Abuse protection switched", "enabled", enabled, "mode", p.Mode, "by", abuseActor(r), "published", published)
	message := "Abuse protection is on, enforcing"
	switch {
	case !enabled:
		message = "Abuse protection is off"
	case p.Mode == abuse.ModeLog:
		message = "Abuse protection is on, logging only"
	}
	writeJSON(w, map[string]any{"status": "success", "message": message, "applies_on_reload": true, "requires_restart": false, "persistent": s.configPath != "", "published": published})
}
