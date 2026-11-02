package abuse

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Alerts and holds are only useful if someone sees them, and nobody watches
// the Abuse page. Whichever service notices something queues a notice in
// Valkey; the MTA, which alone can send mail, takes them off and sends them to
// the addresses in the policy. Without Valkey nothing is queued, as nothing
// else here is shared either.

const (
	keyNotices      = "elemta:abuse:notices"
	keyNoticeBudget = "elemta:abuse:notices:hour:"

	maxQueuedNotices = 200
	// noticesPerHour keeps an attack on many accounts at once from filling
	// the administrator's inbox: past it, one notice says there are more.
	noticesPerHour = 20
	noticePoll     = 10 * time.Second
	maxAlertEmail  = 10
)

// Notice is one email to the administrators.
type Notice struct {
	Time    time.Time `json:"time"`
	Subject string    `json:"subject"`
	Body    string    `json:"body"`
}

// NoticeSender sends a notice to recipients.
type NoticeSender func(ctx context.Context, recipients []string, n Notice) error

// notify queues a notice when the policy names someone to send it to.
func (e *Engine) notify(ctx context.Context, subject, body string) {
	client := e.valkey()
	if client == nil || len(e.Policy().AlertEmail) == 0 {
		return
	}
	hour := keyNoticeBudget + strconv.FormatInt(time.Now().Unix()/3600, 10)
	n, err := client.Do(ctx, client.B().Incr().Key(hour).Build()).AsInt64()
	if err != nil {
		return
	}
	if n == 1 {
		_ = client.Do(ctx, client.B().Expire().Key(hour).Seconds(7200).Build()).Error()
	}
	switch {
	case n == noticesPerHour+1:
		subject = "More abuse alerts this hour"
		body = fmt.Sprintf("More than %d alerts were raised this hour. No more will be emailed until the next hour; the Abuse page in the admin console lists them all.", noticesPerHour)
	case n > noticesPerHour+1:
		return
	}
	raw, err := json.Marshal(Notice{Time: time.Now().UTC(), Subject: subject, Body: body})
	if err != nil {
		return
	}
	if client.Do(ctx, client.B().Lpush().Key(keyNotices).Element(string(raw)).Build()).Error() == nil {
		_ = client.Do(ctx, client.B().Ltrim().Key(keyNotices).Start(0).Stop(maxQueuedNotices-1).Build()).Error()
	}
}

// DeliverNotices sends queued notices until ctx ends. Every MTA runs it; each
// notice is taken by one of them. A notice that can't be sent goes back, to
// be tried again on the next round.
func (e *Engine) DeliverNotices(ctx context.Context, send NoticeSender) {
	ticker := time.NewTicker(noticePoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.deliverQueued(ctx, send)
		}
	}
}

func (e *Engine) deliverQueued(ctx context.Context, send NoticeSender) {
	client := e.valkey()
	recipients := e.Policy().AlertEmail
	if client == nil || len(recipients) == 0 {
		return
	}
	for i := 0; i < maxQueuedNotices; i++ {
		raw, err := client.Do(ctx, client.B().Rpop().Key(keyNotices).Build()).ToString()
		if err != nil {
			return // empty, or Valkey is away
		}
		var n Notice
		if json.Unmarshal([]byte(raw), &n) != nil {
			continue
		}
		if err := send(ctx, recipients, n); err != nil {
			e.log.Warn("Could not send an abuse alert by email; will retry", "error", err)
			_ = client.Do(ctx, client.B().Rpush().Key(keyNotices).Element(raw).Build()).Error()
			return
		}
	}
}

// validAlertEmail checks the addresses alerts go to.
func validAlertEmail(list []string) error {
	if len(list) > maxAlertEmail {
		return fmt.Errorf("alerts can go to at most %d addresses", maxAlertEmail)
	}
	for _, address := range list {
		local, domain, ok := strings.Cut(strings.ToLower(address), "@")
		if !ok || local == "" || !validDomain(domain) || strings.ContainsAny(address, " <>\",;\r\n") {
			return fmt.Errorf("%q is not a mail address", address)
		}
	}
	return nil
}

// alertSubjectBody is the email for a sign-in alert.
func alertSubjectBody(a Alert) (string, string) {
	kinds := map[string]string{AlertTravel: "Impossible travel", AlertNewCountry: "Sign-in from a new country", AlertTargeted: "Account under attack"}
	kind := kinds[a.Kind]
	if kind == "" {
		kind = a.Kind
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n%s\n\n", kind, a.Account, a.Detail)
	fmt.Fprintf(&b, "Address: %s (%s)\nTime: %s\n\n", a.Address, a.Service, a.Time.UTC().Format(time.RFC1123))
	if a.Kind == AlertTargeted {
		b.WriteString("Nothing is locked: the account's owner can still sign in from networks they've used, and with app passwords and passkeys. ")
	} else {
		b.WriteString("Nothing was blocked. If this wasn't the account's owner, change its password and reset two-step sign-in. ")
	}
	b.WriteString("The Abuse page in the admin console has the details and lets you block the address.\n")
	return kind + ": " + a.Account, b.String()
}

// holdSubjectBody is the email for an account put on hold.
func holdSubjectBody(h Hold) (string, string) {
	body := fmt.Sprintf("%s can't send mail outside the server: %s.\n\n"+
		"A taken-over account sends far more than its owner does. Check the account, change its password if it was taken over, "+
		"then release it under Accounts on hold on the Abuse page in the admin console. Mail inside the server still flows.\n", h.Account, h.Reason)
	return "Account on hold: " + h.Account, body
}
