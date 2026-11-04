// Package mailcategory sorts incoming mail into inbox categories: Primary,
// Social, Promotions, Updates and Forums.
//
// The mailbox service classifies each message as it is delivered and records
// the result as a hidden IMAP keyword, so every client sees the same answer
// and nothing is classified twice. The webmail shows the keywords as tabs
// over the inbox.
//
// Classification reads headers only. Mailing list software, bulk senders and
// social networks identify themselves in headers far more reliably than any
// reading of the body could, and headers survive forwarding: mail that a
// Gmail account forwards here keeps the original List-Unsubscribe, List-Id
// and From. Gmail's own category does not travel with it, which is why this
// exists.
//
// A user's corrections win over the rules. Moving a message to another tab
// records its sender, and later mail from that sender lands in that tab.
package mailcategory

import (
	"bufio"
	"bytes"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
)

// Category is one inbox tab. The zero value is Primary.
type Category string

// The categories, in the order the tabs show them.
const (
	Primary    Category = ""
	Social     Category = "social"
	Promotions Category = "promotions"
	Updates    Category = "updates"
	Forums     Category = "forums"
)

// All lists every category, Primary first.
var All = []Category{Primary, Social, Promotions, Updates, Forums}

// Parse returns the category named s, accepting "primary" for Primary.
func Parse(s string) (Category, bool) {
	switch c := Category(strings.ToLower(strings.TrimSpace(s))); c {
	case "primary", Primary:
		return Primary, true
	case Social, Promotions, Updates, Forums:
		return c, true
	}
	return Primary, false
}

// Name is the category as a URL or API value: "primary" for Primary.
func (c Category) Name() string {
	if c == Primary {
		return "primary"
	}
	return string(c)
}

// Label is the tab's title.
func (c Category) Label() string {
	switch c {
	case Social:
		return "Social"
	case Promotions:
		return "Promotions"
	case Updates:
		return "Updates"
	case Forums:
		return "Forums"
	}
	return "Primary"
}

// Keyword is the IMAP keyword that marks a message as being in c, or "" for
// Primary, which is the absence of the others. Keywords starting with $ are
// treated as protocol markers by the webmail and most other clients, so they
// never show up as user tags.
func (c Category) Keyword() string {
	switch c {
	case Social:
		return "$CategorySocial"
	case Promotions:
		return "$CategoryPromotions"
	case Updates:
		return "$CategoryUpdates"
	case Forums:
		return "$CategoryForums"
	}
	return ""
}

// Keywords lists the keywords of every category but Primary.
func Keywords() []string {
	return []string{Social.Keyword(), Promotions.Keyword(), Updates.Keyword(), Forums.Keyword()}
}

// FromKeywords returns the category a message's flags put it in. A message
// carrying more than one (another client set a second) counts as the first
// in tab order, so it shows in exactly one tab.
func FromKeywords(flags []string) Category {
	for _, c := range All[1:] {
		for _, f := range flags {
			if strings.EqualFold(f, c.Keyword()) {
				return c
			}
		}
	}
	return Primary
}

// Overrides maps a sender to the category the user chose for it. A key is
// a lower-case address, or @domain, which also covers the domain's
// subdomains: a rule for @example.com catches news.example.com.
type Overrides map[string]Category

// Lookup returns the user's choice for the address, the most specific rule
// first: the address, then its domain, then each parent domain.
func (o Overrides) Lookup(address string) (Category, bool) {
	if len(o) == 0 {
		return Primary, false
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if c, ok := o[address]; ok {
		return c, true
	}
	_, domain, ok := strings.Cut(address, "@")
	for ok && domain != "" {
		if c, found := o["@"+domain]; found {
			return c, true
		}
		_, domain, ok = strings.Cut(domain, ".")
	}
	return Primary, false
}

// Classify returns the category for a raw RFC 5322 message, given the
// user's overrides (which may be nil). Only the header block is read.
func Classify(raw []byte, overrides Overrides) Category {
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if err != nil && len(h) == 0 {
		return Primary
	}
	return ClassifyHeader(h, overrides)
}

// ClassifyHeader is Classify for a parsed header.
func ClassifyHeader(h textproto.MIMEHeader, overrides Overrides) Category {
	from := fromAddress(h)
	if c, ok := overrides.Lookup(from); ok {
		return c
	}
	_, domain, _ := strings.Cut(from, "@")

	// Order matters. A social network's notification is also automated and
	// carries List-Unsubscribe; a discussion list is also bulk mail. The
	// most specific signal decides.
	if isForum(h) {
		return Forums
	}
	if matchesDomain(domain, socialDomains) {
		return Social
	}
	bulk := h.Get("List-Unsubscribe") != "" || isBulkPrecedence(h) || h.Get("List-Id") != ""
	transactional := isTransactional(h)
	switch {
	case bulk && transactional:
		// Receipts and shipping notices from shops carry an unsubscribe link
		// too. The subject says which it is.
		return Updates
	case bulk && isMarketing(h, domain):
		return Promotions
	case bulk:
		// Bulk mail with no marketing signal: newsletters, digests and
		// account notices. Gmail files most of these in Updates unless the
		// sender is a marketing platform.
		if h.Get("List-Unsubscribe") != "" && !isAutomatedSender(from) {
			return Promotions
		}
		return Updates
	case transactional, isAutoSubmitted(h), isAutomatedSender(from):
		return Updates
	}
	return Primary
}

func fromAddress(h textproto.MIMEHeader) string {
	v := h.Get("From")
	if v == "" {
		return ""
	}
	if a, err := mail.ParseAddress(v); err == nil {
		return strings.ToLower(a.Address)
	}
	if list, err := mail.ParseAddressList(v); err == nil && len(list) > 0 {
		return strings.ToLower(list[0].Address)
	}
	// An unparseable From still often holds an address in angle brackets.
	if i, j := strings.LastIndex(v, "<"), strings.LastIndex(v, ">"); i >= 0 && j > i {
		return strings.ToLower(strings.TrimSpace(v[i+1 : j]))
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// isForum reports discussion list mail: people writing to each other through
// a list. List-Post is the clearest sign, because only lists that take posts
// set it; marketing platforms set List-Id and List-Unsubscribe but never it.
func isForum(h textproto.MIMEHeader) bool {
	if lp := strings.TrimSpace(h.Get("List-Post")); lp != "" && !strings.EqualFold(lp, "NO") {
		return true
	}
	for _, k := range []string{"X-Mailman-Version", "X-Google-Group-Id", "X-Discourse-Post-Id", "X-Groups-Io-Id", "X-Mailing-List"} {
		if h.Get(k) != "" {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(h.Get("Precedence")), "list") && h.Get("List-Id") != ""
}

func isBulkPrecedence(h textproto.MIMEHeader) bool {
	switch strings.ToLower(strings.TrimSpace(h.Get("Precedence"))) {
	case "bulk", "junk", "list":
		return true
	}
	return false
}

func isAutoSubmitted(h textproto.MIMEHeader) bool {
	v := strings.ToLower(strings.TrimSpace(h.Get("Auto-Submitted")))
	return v != "" && v != "no"
}

// automatedLocal matches the local parts automated senders use.
var automatedLocal = regexp.MustCompile(`^(no-?reply|do-?not-?reply|donotreply|notifications?|notify|alerts?|updates?|mailer|automated|auto-?confirm|accounts?|account-?security|security|billing|receipts?|orders?|shipping|support|service|system|admin|bounce.*|mailer-daemon|postmaster)([+._-].*)?$`)

func isAutomatedSender(from string) bool {
	local, _, _ := strings.Cut(from, "@")
	return local != "" && automatedLocal.MatchString(local)
}

// transactionalSubject matches subjects of mail that reports on something
// the user did or owns, rather than selling to them.
var transactionalSubject = regexp.MustCompile(`(?i)\b(receipt|invoice|order (confirm|#|number|no\.?)|your order|has shipped|shipped|out for delivery|delivered|tracking|payment (received|confirm|due|failed)|statement|bill is (ready|due)|password|verification|verify your|confirm your|security (alert|code|notice)|sign[- ]in|log[- ]?in (attempt|alert)|one[- ]time (code|passcode)|reservation|booking|itinerary|appointment|renewal|subscription (confirm|renew)|account (update|notice|alert))\b`)

func isTransactional(h textproto.MIMEHeader) bool {
	if transactionalSubject.MatchString(h.Get("Subject")) {
		return true
	}
	// A dedicated transactional stream: several providers put "transactional"
	// in the Feedback-ID campaign field or a stream header.
	for _, k := range []string{"Feedback-ID", "X-PM-Message-Stream", "X-Mailgun-Tag", "X-SES-Configuration-Set"} {
		if strings.Contains(strings.ToLower(h.Get(k)), "transactional") {
			return true
		}
	}
	return false
}

// marketingHeaders are headers only marketing platforms add.
var marketingHeaders = []string{
	"X-Mailchimp-Campaign", "X-MC-User", "X-Campaign", "X-CampaignID", "X-Campaign-Id",
	"X-Klaviyo-Message-Id", "X-Kmail-Account", "X-Braze-Campaign", "X-HubSpot-Campaign",
	"X-Iterable-Campaign", "X-Marketo-Id", "X-SFMC-Stack", "X-Mailin-Campaign", "X-Sib-Id",
	"X-CSA-Complaints", "X-Constant-Contact", "X-Roving-Id", "X-Emarsys-Id",
}

// marketingMailers are names in X-Mailer of platforms that send campaigns.
var marketingMailers = regexp.MustCompile(`(?i)mailchimp|mandrill|klaviyo|braze|hubspot|marketo|sendinblue|brevo|constant ?contact|campaign ?monitor|createsend|iterable|customer\.io|salesforce marketing|exacttarget|emarsys|acoustic|silverpop|omnisend|mailerlite|convertkit|activecampaign|drip|moosend|getresponse|aweber`)

// marketingDomains are sending domains of marketing platforms, matched
// against From and Return-Path.
var marketingDomains = []string{
	"mailchimpapp.net", "mcsv.net", "mcdlv.net", "rsgsv.net", "list-manage.com",
	"klaviyomail.com", "klaviyo.com", "hubspotemail.net", "hs-email.net", "sendgrid.net",
	"exacttarget.com", "e.salesforce.com", "mktomail.com", "mkt.com", "cmail19.com", "cmail20.com",
	"createsend.com", "sendinblue.com", "brevosend.com", "rmail.ctct.com", "constantcontact.com",
	"emarsys.net", "iterable.com", "braze.com", "customeriomail.com", "omnisend.com",
	"mailerlite.com", "convertkit-mail.com", "acemsrvc.com", "bmsend.com",
}

func isMarketing(h textproto.MIMEHeader, fromDomain string) bool {
	for _, k := range marketingHeaders {
		if h.Get(k) != "" {
			return true
		}
	}
	if marketingMailers.MatchString(h.Get("X-Mailer")) {
		return true
	}
	if matchesDomain(fromDomain, marketingDomains) {
		return true
	}
	rp := strings.Trim(strings.TrimSpace(h.Get("Return-Path")), "<>")
	if _, d, ok := strings.Cut(rp, "@"); ok && matchesDomain(strings.ToLower(d), marketingDomains) {
		return true
	}
	// Feedback-ID is "a:b:c:SenderId"; senders who use it to separate
	// campaigns tend to name them.
	fb := strings.ToLower(h.Get("Feedback-ID"))
	return strings.Contains(fb, "campaign") || strings.Contains(fb, "marketing") || strings.Contains(fb, "newsletter") || strings.Contains(fb, "promo")
}

// socialDomains send notifications from social networks and community sites.
var socialDomains = []string{
	"facebookmail.com", "facebook.com", "instagram.com", "mail.instagram.com", "linkedin.com",
	"x.com", "twitter.com", "pinterest.com", "reddit.com", "redditmail.com", "tiktok.com",
	"snapchat.com", "tumblr.com", "quora.com", "nextdoor.com", "meetup.com", "discord.com",
	"discordapp.com", "threads.net", "bsky.app", "youtube.com", "twitch.tv", "strava.com",
	"goodreads.com", "flickr.com", "vk.com", "ok.ru", "wechat.com", "line.me", "mastodon.social",
}

// matchesDomain reports whether domain is one of list or a subdomain of one.
func matchesDomain(domain string, list []string) bool {
	if domain == "" {
		return false
	}
	for _, d := range list {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
