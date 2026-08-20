package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/EvalAlan/elemta/internal/suppression"
)

// The suppression list in the dashboard.
//
// Two things an operator needs from it, and they pull in opposite directions:
// confidence that mail is not going to addresses that bounced, and a way to put
// an address back when it was suppressed in error. Both are here; neither is
// automatic.

func (s *Server) handleListSuppressed(w http.ResponseWriter, r *http.Request) {
	store := s.suppressionStore()
	if store == nil {
		http.Error(w, "The suppression list is not available", http.StatusServiceUnavailable)
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	entries, total, err := store.List(r.Context(), query, limit, offset)
	if err != nil {
		http.Error(w, "Could not read the suppression list: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"suppressed": entries,
		"total":      total,
		"offset":     offset,
		"query":      query,
	})
}

// handleSuppressAddress adds an address by hand.
//
// Worth having even though most entries arrive from bounces: an operator who
// has been told by a person to stop mailing them should be able to act on that
// immediately, rather than waiting for a complaint to arrive through a feedback
// loop that may not exist.
func (s *Server) handleSuppressAddress(w http.ResponseWriter, r *http.Request) {
	store := s.suppressionStore()
	if store == nil {
		http.Error(w, "The suppression list is not available", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Address string `json:"address"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	address := suppression.Normalize(body.Address)
	if address == "" || !strings.Contains(address, "@") {
		http.Error(w, "A valid email address is required", http.StatusBadRequest)
		return
	}

	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "added by an operator"
	}
	if err := store.Add(r.Context(), suppression.Entry{
		Address: address, Source: suppression.SourceManual, Reason: reason,
	}); err != nil {
		http.Error(w, "Could not suppress the address: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{"status": "success", "address": address})
}

// handleUnsuppressAddress takes an address off the list.
//
// Deliberately a separate action rather than something that expires on its own:
// an address that starts receiving mail again because enough time passed is the
// bug this list exists to prevent, arriving quietly.
func (s *Server) handleUnsuppressAddress(w http.ResponseWriter, r *http.Request) {
	store := s.suppressionStore()
	if store == nil {
		http.Error(w, "The suppression list is not available", http.StatusServiceUnavailable)
		return
	}

	address := suppression.Normalize(mux.Vars(r)["address"])
	if address == "" {
		http.Error(w, "An address is required", http.StatusBadRequest)
		return
	}

	removed, err := store.Remove(r.Context(), address)
	if err != nil {
		http.Error(w, "Could not remove the address: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "That address is not on the suppression list", http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]interface{}{"status": "success", "address": address})
}
