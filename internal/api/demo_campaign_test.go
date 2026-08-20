package api

import (
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/campaign"
)

// Seeded content is a liability unless it cannot act on its own and cannot get
// in the way of real work, so that is what these check.

func TestDemoCampaignOnlyWhenAskedFor(t *testing.T) {
	store := campaign.NewStore()
	// No environment variable: a production deployment must not invent content
	// it did not ask for.
	if seedDemoCampaign(store, "mail.example.com") {
		t.Error("the demo was seeded without ELEMTA_DEMO_DATA")
	}
	if len(store.List()) != 0 {
		t.Error("nothing should have been added")
	}

	t.Setenv(demoCampaignEnv, "true")
	if !seedDemoCampaign(store, "mail.example.com") {
		t.Fatal("the demo was not seeded with ELEMTA_DEMO_DATA=true")
	}
	if len(store.List()) != 1 {
		t.Fatalf("got %d campaigns, want 1", len(store.List()))
	}
}

// TestDemoCampaignNeverSendsByItself is the property that matters most: a
// deployment that mailed people because it booted would be indefensible.
func TestDemoCampaignNeverSendsByItself(t *testing.T) {
	t.Setenv(demoCampaignEnv, "true")
	store := campaign.NewStore()
	seedDemoCampaign(store, "mail.example.com")

	demo := store.List()[0]
	if demo.State != campaign.StateDraft {
		t.Errorf("state = %q, want draft", demo.State)
	}
	if demo.Sent != 0 || demo.StartedAt != nil {
		t.Errorf("the demo looks as though it has run: sent=%d started=%v", demo.Sent, demo.StartedAt)
	}
}

// TestDemoCampaignStaysLocal: someone will press Start out of curiosity, and
// when they do it should reach this stack's own Dovecot rather than strangers.
func TestDemoCampaignStaysLocal(t *testing.T) {
	t.Setenv(demoCampaignEnv, "true")
	store := campaign.NewStore()
	seedDemoCampaign(store, "mail.example.com")

	for _, r := range store.List()[0].Recipients {
		if !strings.HasSuffix(r.Email, "@example.com") {
			t.Errorf("recipient %q is not a local development mailbox", r.Email)
		}
	}
}

// TestDemoCampaignDoesNotDisplaceRealWork: seeding into a store that already
// holds something would put demo content beside an operator's own campaign.
func TestDemoCampaignDoesNotDisplaceRealWork(t *testing.T) {
	t.Setenv(demoCampaignEnv, "true")
	store := campaign.NewStore()
	store.Put(&campaign.Campaign{ID: "real", Name: "Real campaign", State: campaign.StateDraft})

	if seedDemoCampaign(store, "mail.example.com") {
		t.Error("the demo was seeded into a store that was not empty")
	}
	if len(store.List()) != 1 {
		t.Errorf("got %d campaigns, want only the real one", len(store.List()))
	}
}

// TestDemoCampaignIsValidAndDemonstrates: an example that cannot be started, or
// that shows none of the features, teaches the wrong things.
func TestDemoCampaignIsValidAndDemonstrates(t *testing.T) {
	t.Setenv(demoCampaignEnv, "true")
	store := campaign.NewStore()
	seedDemoCampaign(store, "mail.example.com")
	demo := store.List()[0]

	if err := demo.Validate(); err != nil {
		t.Errorf("the demo should be a campaign someone could actually start: %v", err)
	}
	// Both body parts: HTML alone is the most common way bulk mail looks like
	// bulk mail to a filter.
	if strings.TrimSpace(demo.HTMLBody) == "" || strings.TrimSpace(demo.TextBody) == "" {
		t.Error("the demo should show both an HTML and a plain text alternative")
	}
	// Merge fields, and every one of them supplied by the recipient list — an
	// example that ships with an unresolved placeholder teaches the bug.
	unresolved := campaign.UnresolvedFields(
		demo.Subject+" "+demo.HTMLBody+" "+demo.TextBody, demo.Recipients)
	if len(unresolved) > 0 {
		t.Errorf("the demo has merge fields nothing supplies: %v", unresolved)
	}
	if !strings.Contains(demo.Subject, "{{") {
		t.Error("the subject should show a merge field, where an unresolved one is most visible")
	}
}
