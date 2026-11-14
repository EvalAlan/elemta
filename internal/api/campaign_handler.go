package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/EvalAlan/elemta/internal/campaign"
)

// Campaign endpoints.
//
// Creating a campaign and running one are deliberately separate: a campaign is
// composed, checked and only then started, so nothing is sent by the request
// that merely saved a draft.

// campaignRequest is the editable shape of a campaign. Progress and state are
// not accepted from the client — they are the server's account of what has
// actually happened, and letting a client set them would let it claim a
// campaign had been sent.
type campaignRequest struct {
	Name          string `json:"name"`
	From          string `json:"from"`
	ReplyTo       string `json:"reply_to"`
	Subject       string `json:"subject"`
	HTMLBody      string `json:"html_body"`
	TextBody      string `json:"text_body"`
	RatePerMinute int    `json:"rate_per_minute"`
	// Recipients is the raw pasted or uploaded list, parsed server-side so the
	// same rules apply however it arrived.
	Recipients string `json:"recipients"`
}

func (s *Server) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	store, _ := s.massMailer()
	if store == nil {
		http.Error(w, "Mass mailer is not enabled", http.StatusServiceUnavailable)
		return
	}
	list := store.List()
	summaries := make([]map[string]interface{}, 0, len(list))
	for _, c := range list {
		summaries = append(summaries, campaignSummary(c))
	}
	writeJSON(w, map[string]interface{}{"campaigns": summaries})
}

func (s *Server) handleGetCampaign(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCampaign(w, r)
	if !ok {
		return
	}
	full := campaignSummary(c)
	full["html_body"] = c.HTMLBody
	full["text_body"] = c.TextBody
	full["reply_to"] = c.ReplyTo
	// The full recipient list can be very large; the UI asks for it separately.
	writeJSON(w, full)
}

// handleGetCampaignRecipients returns the parsed list, which the UI shows as a
// preview so the operator can see who they are about to mail.
func (s *Server) handleGetCampaignRecipients(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCampaign(w, r)
	if !ok {
		return
	}
	// Large enough that an ordinary campaign comes back whole. The UI edits the
	// list it is given, so a low limit would make most campaigns read-only:
	// saving a truncated list back would replace the stored one with the
	// fragment on screen. Past this size the UI says so and stops editing.
	const limit = 5000
	recipients := c.Recipients
	truncated := false
	if len(recipients) > limit {
		recipients = recipients[:limit]
		truncated = true
	}
	writeJSON(w, map[string]interface{}{
		"recipients": recipients,
		"total":      c.Total(),
		"truncated":  truncated,
	})
}

func (s *Server) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
	store, _ := s.massMailer()
	if store == nil {
		http.Error(w, "Mass mailer is not enabled", http.StatusServiceUnavailable)
		return
	}
	var req campaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	c := &campaign.Campaign{
		ID:        uuid.New().String(),
		State:     campaign.StateDraft,
		CreatedBy: abuseActor(r),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	warnings, err := applyCampaignRequest(c, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.checkCampaignSender(c.From); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	store.Put(c)
	response := campaignSummary(c)
	response["warnings"] = warnings
	writeJSON(w, response)
}

func (s *Server) handleUpdateCampaign(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCampaign(w, r)
	if !ok {
		return
	}
	// Editing a campaign mid-flight would change the message some recipients
	// have already received, so the copies would differ with no record of it.
	if c.State == campaign.StateRunning {
		http.Error(w, "A running campaign cannot be edited; pause it first", http.StatusConflict)
		return
	}

	var req campaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	store, _ := s.massMailer()
	if store == nil {
		http.Error(w, "Mass mailer is not enabled", http.StatusServiceUnavailable)
		return
	}
	stored, ok := store.Get(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "Campaign not found", http.StatusNotFound)
		return
	}
	if err := s.checkCampaignSender(strings.TrimSpace(req.From)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	warnings, err := applyCampaignRequest(stored, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	response := campaignSummary(stored.Clone())
	response["warnings"] = warnings
	writeJSON(w, response)
}

func (s *Server) handleDeleteCampaign(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCampaign(w, r)
	if !ok {
		return
	}
	if c.State == campaign.StateRunning {
		http.Error(w, "A running campaign cannot be deleted; cancel it first", http.StatusConflict)
		return
	}
	if store, _ := s.massMailer(); store != nil {
		store.Delete(c.ID)
	}
	writeJSON(w, map[string]string{"status": "success", "id": c.ID})
}

// handleCampaignAction drives the state machine: start, pause, cancel, test.
func (s *Server) handleCampaignAction(w http.ResponseWriter, r *http.Request) {
	store, runner := s.massMailer()
	if store == nil || runner == nil {
		http.Error(w, "Mass mailer is not enabled", http.StatusServiceUnavailable)
		return
	}
	stored, ok := store.Get(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "Campaign not found", http.StatusNotFound)
		return
	}

	action := mux.Vars(r)["action"]
	actor := abuseActor(r)
	// Checked again when mail is about to go out: the allowed senders or the
	// hosted domains may have changed since the campaign was saved.
	if action == "start" || action == "test" {
		if err := s.checkCampaignSender(stored.Clone().From); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	var err error
	switch action {
	case "start":
		err = runner.Start(stored)
		if err == nil {
			stored.SetStartedBy(actor)
			snap := stored.Clone()
			slog.Info("Campaign started", "campaign", snap.ID, "name", snap.Name, "from", snap.From,
				"recipients", snap.Total(), "rate_per_minute", snap.RatePerMinute, "by", actor)
		}
	case "pause":
		err = runner.Pause(stored)
		if err == nil {
			slog.Info("Campaign paused", "campaign", stored.ID, "by", actor)
		}
	case "cancel":
		err = runner.Cancel(stored)
		if err == nil {
			slog.Info("Campaign cancelled", "campaign", stored.ID, "by", actor)
		}
	case "test":
		var body struct {
			To string `json:"to"`
		}
		if decodeErr := json.NewDecoder(r.Body).Decode(&body); decodeErr != nil || strings.TrimSpace(body.To) == "" {
			http.Error(w, "A 'to' address is required for a test send", http.StatusBadRequest)
			return
		}
		err = runner.SendTest(stored, strings.TrimSpace(body.To))
		if err == nil {
			slog.Info("Campaign test sent", "campaign", stored.ID, "to", strings.TrimSpace(body.To), "by", actor)
		}
	default:
		http.Error(w, fmt.Sprintf("Unknown action %q", action), http.StatusBadRequest)
		return
	}

	if err != nil {
		// These are refusals the operator can act on — wrong state, invalid
		// campaign — rather than server faults.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := campaignSummary(stored.Clone())
	response["action"] = action
	writeJSON(w, response)
}

func (s *Server) lookupCampaign(w http.ResponseWriter, r *http.Request) (*campaign.Campaign, bool) {
	store, _ := s.massMailer()
	if store == nil {
		http.Error(w, "Mass mailer is not enabled", http.StatusServiceUnavailable)
		return nil, false
	}
	stored, ok := store.Get(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "Campaign not found", http.StatusNotFound)
		return nil, false
	}
	return stored.Clone(), true
}

// applyCampaignRequest copies the editable fields onto a campaign and parses
// the recipient list, returning warnings worth showing before sending.
func applyCampaignRequest(c *campaign.Campaign, req *campaignRequest) ([]string, error) {
	c.Name = strings.TrimSpace(req.Name)
	c.From = strings.TrimSpace(req.From)
	c.ReplyTo = strings.TrimSpace(req.ReplyTo)
	c.Subject = req.Subject
	c.HTMLBody = req.HTMLBody
	c.TextBody = req.TextBody
	c.RatePerMinute = req.RatePerMinute
	c.UpdatedAt = time.Now().UTC()

	var warnings []string
	if strings.TrimSpace(req.Recipients) != "" {
		recipients, problems, err := campaign.ParseRecipients(req.Recipients)
		if err != nil {
			return nil, err
		}
		campaign.SortRecipients(recipients)
		c.Recipients = recipients

		// Malformed lines are reported rather than dropped in silence: an
		// operator who is not told believes they mailed a list they did not.
		if len(problems) > 0 {
			shown := problems
			if len(shown) > 10 {
				shown = shown[:10]
			}
			warnings = append(warnings,
				fmt.Sprintf("%d line(s) were skipped: %s", len(problems), strings.Join(shown, "; ")))
		}
	}

	// Merge fields nobody supplies render as blanks, which is visible in the
	// delivered mail — so it is worth saying before the campaign goes out.
	for _, field := range campaign.UnresolvedFields(c.Subject+" "+c.HTMLBody+" "+c.TextBody, c.Recipients) {
		warnings = append(warnings,
			fmt.Sprintf("no recipient supplies {{%s}}; it will render empty", field))
	}

	return warnings, nil
}

// campaignSummary is the wire shape: enough to render a list row or a progress
// display, without the bodies or the full recipient list.
func campaignSummary(c *campaign.Campaign) map[string]interface{} {
	return map[string]interface{}{
		"id":              c.ID,
		"name":            c.Name,
		"from":            c.From,
		"subject":         c.Subject,
		"state":           string(c.State),
		"total":           c.Total(),
		"sent":            c.Sent,
		"failed":          c.Failed,
		"skipped":         c.Skipped,
		"remaining":       c.Remaining(),
		"rate_per_minute": c.RatePerMinute,
		"last_error":      c.LastError,
		"created_by":      c.CreatedBy,
		"started_by":      c.StartedBy,
		"created_at":      c.CreatedAt,
		"updated_at":      c.UpdatedAt,
		"started_at":      c.StartedAt,
		"completed_at":    c.CompletedAt,
	}
}

// checkCampaignSender refuses a From the mass mailer may not send as
// (campaign.SenderAllowed), saying how to allow it.
func (s *Server) checkCampaignSender(from string) error {
	if from == "" {
		return nil // Validate reports the missing address when it matters
	}
	var allowed []string
	if s.mainConfig != nil && s.mainConfig.MassMailer != nil {
		allowed = s.mainConfig.MassMailer.AllowedSenders
	}
	if campaign.SenderAllowed(from, s.localDomains(), allowed) {
		return nil
	}
	if len(allowed) == 0 {
		return fmt.Errorf("campaigns can't be sent from %s: its domain isn't hosted here. Add it under the Mass Mailer's allowed senders to send as it", from)
	}
	return fmt.Errorf("campaigns can't be sent from %s: it isn't one of the Mass Mailer's allowed senders", from)
}
