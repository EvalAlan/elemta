package api

import (
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/EvalAlan/elemta/internal/campaign"
)

// A worked example in the mass mailer.
//
// The Mass Mailer opens on an empty list, which shows nothing about what a
// campaign is: not the merge fields, not the HTML and text alternatives, not
// what the editor does with a recipient list. A ready-made draft answers all of
// that by being opened.
//
// Seeded by the server rather than created through the API because campaigns
// live in memory — deliberately, since a campaign is an operator action in
// progress rather than a system of record. A demo inserted once by a deploy
// script would vanish at the first restart, which is a worse first impression
// than no demo at all.
//
// Three properties keep this from being a liability:
//
//   - It is a draft and is never started. A deployment that mails anybody
//     because it booted would be indefensible.
//   - Its recipients are the development stack's own mailboxes, so pressing
//     Start out of curiosity delivers to the local Dovecot rather than to
//     strangers.
//   - It is only seeded into an empty store, so it can never displace or sit
//     alongside real work.
//
// Gated on ELEMTA_DEMO_DATA, set only in the development compose file, so no
// production deployment invents content it did not ask for.

const demoCampaignEnv = "ELEMTA_DEMO_DATA"

// seedDemoCampaign adds a worked example to an empty store.
func seedDemoCampaign(store *campaign.Store, hostname string) bool {
	if os.Getenv(demoCampaignEnv) != "true" || store == nil {
		return false
	}
	if len(store.List()) > 0 {
		return false
	}

	now := time.Now().UTC()
	demo := &campaign.Campaign{
		ID:      uuid.New().String(),
		Name:    "Example newsletter (demo)",
		From:    "Elemta Demo <newsletter@" + hostname + ">",
		ReplyTo: "",
		// The merge field is in the subject on purpose: it is the first place
		// an unresolved placeholder embarrasses someone, and seeing it work
		// here explains the feature faster than the hint text does.
		Subject: "{{first_name}}, here is what changed this month",
		HTMLBody: `<h2>Hello {{first_name}},</h2>
<p>This is a demonstration campaign. It has not been sent to anyone, and its
recipients are mailboxes belonging to this development stack.</p>
<p>Things worth trying from here:</p>
<ul>
  <li>Edit this text, or switch to <strong>HTML</strong> to see the source.</li>
  <li>Use <strong>Preview</strong> to see it as a mail client would, with the
      merge fields filled in from the first recipient.</li>
  <li>Add a recipient below and watch the merge field chips update.</li>
  <li>Send a test to yourself before starting anything.</li>
</ul>
<p>You are in {{city}}, according to the recipient list.</p>
<p>— The Elemta demo</p>`,
		TextBody: `Hello {{first_name}},

This is a demonstration campaign. It has not been sent to anyone, and its
recipients are mailboxes belonging to this development stack.

Things worth trying from here:

- Edit this text, or switch to HTML to see the source.
- Use Preview to see it as a mail client would, with the merge fields filled
  in from the first recipient.
- Add a recipient below and watch the merge field chips update.
- Send a test to yourself before starting anything.

You are in {{city}}, according to the recipient list.

-- The Elemta demo`,
		// Both parts are filled in because a campaign with only HTML is the
		// most common way bulk mail looks like bulk mail to a filter.
		Recipients: []campaign.Recipient{
			{Email: "demo@example.com", Vars: map[string]string{"first_name": "Dana", "city": "Berlin"}},
			{Email: "user@example.com", Vars: map[string]string{"first_name": "Sam", "city": "Lisbon"}},
		},
		RatePerMinute: 60,
		State:         campaign.StateDraft,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	store.Put(demo)
	return true
}
