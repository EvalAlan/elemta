package api

// Log shipping in the console (internal/logship): the settings, how it's
// going, and a test. It needs sign-in configured: where logs go is a place
// this process makes requests to, carrying a credential.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/logship"
	"github.com/gorilla/mux"
)

const (
	logShipFailingAfter = 5 * time.Minute
	logShipDropWindow   = time.Hour
	logShipView         = "settings/plugin-log_shipping"
)

// SetLogShipper connects log shipping.
func (s *Server) SetLogShipper(l *logship.Shipper) { s.logShip = l }

func (s *Server) logShipRoutes(api *mux.Router) {
	if s.authMiddleware == nil {
		return
	}
	configure := s.authMiddleware.RequirePermission(auth.PermissionSystemConfig)
	api.Handle("/log-shipping", configure(http.HandlerFunc(s.handleLogShip))).Methods("GET")
	api.Handle("/log-shipping", configure(http.HandlerFunc(s.handleLogShipSave))).Methods("PUT")
	api.Handle("/log-shipping/test", configure(http.HandlerFunc(s.handleLogShipTest))).Methods("POST")
}

func (s *Server) runLogShipping(stop <-chan struct{}) {
	if s.logShip == nil || s.authMiddleware == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	s.logShip.Run(ctx)
}

func (s *Server) logShipPlugin() map[string]any {
	set, _, err := s.logShip.Settings()
	if err != nil {
		slog.Warn("Log shipping settings can't be read", "error", err)
	}
	return map[string]any{
		"name": "log_shipping", "title": "Log shipping", "enabled": set.Enabled,
		"description":  "Send every service's log to Elasticsearch or Logstash, with secrets redacted",
		"configurable": true,
		// Off, it still needs its tab: that's where it's set up.
		"needs_config":     !set.Enabled,
		"requires_restart": false,
	}
}

func (s *Server) handleLogShip(w http.ResponseWriter, r *http.Request) {
	if s.logShip == nil {
		http.Error(w, "Log shipping is not available", http.StatusServiceUnavailable)
		return
	}
	set, _, err := s.logShip.Settings()
	if err != nil {
		slog.Error("Log shipping settings can't be read", "error", err)
		http.Error(w, "The settings can't be read", http.StatusInternalServerError)
		return
	}
	status, err := s.logShip.Status(r.Context())
	if err != nil {
		slog.Error("Log shipping status can't be read", "error", err)
		http.Error(w, "The status can't be read", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"settings": set, "status": status, "destinations": s.logShip.Destinations()})
}

type logShipRequest struct {
	Settings logship.Settings `json:"settings"`
	// Credential left out keeps the saved one; empty clears it.
	Credential *logship.Credential `json:"credential"`
}

func (s *Server) decodeLogShip(w http.ResponseWriter, r *http.Request) (logShipRequest, bool) {
	var req logShipRequest
	if s.logShip == nil {
		http.Error(w, "Log shipping is not available", http.StatusServiceUnavailable)
		return req, false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		// Not the decoder's own words: they can quote what was sent.
		http.Error(w, "Invalid log shipping settings", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (s *Server) handleLogShipSave(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeLogShip(w, r)
	if !ok {
		return
	}
	s.saveLogShipping(w, r, req.Settings, req.Credential)
}

func (s *Server) setLogShipPlugin(w http.ResponseWriter, r *http.Request, enabled bool) {
	if s.logShip == nil || s.authMiddleware == nil {
		http.Error(w, "Log shipping is not available", http.StatusServiceUnavailable)
		return
	}
	set, _, err := s.logShip.Settings()
	if err != nil {
		slog.Error("Log shipping settings can't be read", "error", err)
		http.Error(w, "The settings can't be read", http.StatusInternalServerError)
		return
	}
	set.Enabled = enabled
	s.saveLogShipping(w, r, set, nil)
}

func (s *Server) saveLogShipping(w http.ResponseWriter, r *http.Request, set logship.Settings, c *logship.Credential) {
	if err := s.logShip.Save(r.Context(), set, c); err != nil {
		if logship.IsInvalid(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		slog.Error("Failed to save log shipping", "error", err)
		http.Error(w, "Failed to save the settings", http.StatusInternalServerError)
		return
	}
	set = set.WithDefaults()
	slog.Info("Log shipping changed", "enabled", set.Enabled, "kind", set.Kind, "destination", set.URL,
		"min_level", set.MinLevel, "include_subjects", set.IncludeSubjects, "by", abuseActor(r))
	message := "Log shipping is off"
	if set.Enabled {
		message = "Log shipping is on; every service follows within seconds"
	}
	writeJSON(w, map[string]any{"status": "success", "message": message, "persistent": true, "requires_restart": false})
}

func (s *Server) handleLogShipTest(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeLogShip(w, r)
	if !ok {
		return
	}
	if err := s.logShip.Test(r.Context(), req.Settings, req.Credential); err != nil {
		code := http.StatusBadGateway
		if logship.IsInvalid(err) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	slog.Info("Log shipping tested", "by", abuseActor(r))
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) logShipAttention(ctx context.Context, now time.Time) []attentionItem {
	if s.logShip == nil || s.authMiddleware == nil {
		return nil
	}
	const title = "Log shipping"
	set, _, err := s.logShip.Settings()
	if err != nil {
		return []attentionItem{couldNotCheck(title, "its settings can't be read.", logShipView)}
	}
	if !set.Enabled {
		return nil
	}
	st, err := s.logShip.Status(ctx)
	if err != nil || !st.Available {
		return []attentionItem{couldNotCheck(title, "Valkey, which carries the logs, didn't answer.", logShipView)}
	}
	var out []attentionItem
	if st.FailingSince != nil && now.Sub(*st.FailingSince) >= logShipFailingAfter {
		out = append(out, attentionItem{Severity: attentionWarning, Title: title, View: logShipView,
			Since: st.FailingSince.Format(time.RFC3339), Detail: "Logs aren't reaching the destination. " + st.LastError})
	}
	if st.LastDropped != nil && now.Sub(*st.LastDropped) < logShipDropWindow {
		out = append(out, attentionItem{Severity: attentionWarning, Title: title, View: logShipView,
			Since: st.LastDropped.Format(time.RFC3339), Detail: "The queue was full and log lines were dropped."})
	}
	return out
}
