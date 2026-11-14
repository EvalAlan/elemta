package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// Campaigns go out From a hosted domain unless the operator names other
// senders; recipients are never limited. Saving, starting and test-sending
// all check, and the console user who created a campaign is recorded.
func TestCampaignSenders(t *testing.T) {
	s := &Server{mainConfig: &MainConfig{Hostname: "mail.example.com", LocalDomains: []string{"example.com"},
		MassMailer: &MassMailerStatus{Enabled: true, DefaultRatePerMinute: 600}}}
	if err := s.setMassMailerEnabled(true); err != nil {
		t.Fatal(err)
	}
	router := mux.NewRouter()
	router.HandleFunc("/campaigns", s.handleCreateCampaign).Methods("POST")
	router.HandleFunc("/campaigns/{id}/{action}", s.handleCampaignAction).Methods("POST")
	create := func(from string) (int, map[string]any) {
		body, _ := json.Marshal(map[string]any{"name": "News", "from": from, "subject": "Hi",
			"text_body": "hello", "recipients": "someone@outside.example"})
		req := httptest.NewRequest("POST", "/campaigns", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), authContextKey, &AuthContext{Username: "ops"}))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	if code, out := create("News <news@example.com>"); code != http.StatusOK || out["created_by"] != "ops" {
		t.Fatalf("hosted sender, outside recipient: %d %v", code, out)
	}
	if code, _ := create("ceo@bank.example"); code != http.StatusBadRequest {
		t.Fatalf("unhosted sender accepted: %d", code)
	}

	s.mainConfig.MassMailer.AllowedSenders = []string{"brand.example"}
	code, out := create("news@brand.example")
	if code != http.StatusOK {
		t.Fatalf("listed outside domain refused: %d", code)
	}
	// Narrowed again before the send: start and test refuse.
	s.mainConfig.MassMailer.AllowedSenders = []string{"news@example.com"}
	for _, action := range []string{"start", "test"} {
		req := httptest.NewRequest("POST", "/campaigns/"+out["id"].(string)+"/"+action, strings.NewReader(`{"to":"me@example.com"}`))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "allowed senders") {
			t.Errorf("%s with a sender no longer allowed: %d %s", action, rec.Code, rec.Body.String())
		}
	}
}
