package api

import "strings"

// logCategories groups every event_type the services write into the
// categories the Logs tab filters by.
//
// The tab used to keep only seven types (reception, delivery, rejection,
// deferral, bounce, tempfail, authentication) plus untyped lines, warnings and
// errors. Every other type at info level was dropped before the filter even
// ran: on the dev server that was most of the mail's own story, among them
// message_received and message_accepted (the reception steps), scan results,
// spam_detected and suppressions, and later the mailbox and webmail session
// lines. A type that isn't listed here falls under system rather than
// vanishing, so a new one shows up in the tab from the day it is logged.
var logCategories = map[string]string{
	"reception":        "reception",
	"message_received": "reception",
	"message_accepted": "reception",
	"submission":       "reception", // the webmail handing a message over to send

	"mail_from_accepted": "session",
	"rcpt_to_accepted":   "session",
	"data_accepted":      "session",

	"delivery": "delivery",
	"deferral": "deferral",
	"tempfail": "tempfail",

	"bounce":      "bounce",
	"suppression": "bounce", // an address suppressed after it bounced

	"rejection": "rejection",

	"scan":                 "scan",
	"spam_detected":        "scan",
	"virus_detected":       "scan",
	"dangerous_attachment": "scan",
	"quarantine":           "scan",

	"security":                  "security",
	"desynchronization_attempt": "security",
	"smtp_smuggling_attempt":    "security",
	"rfc_violation":             "security",
	"suspicious_pattern":        "security",
	"protocol_error":            "security",
	"policy":                    "security",

	"authentication": "authentication",
	"logout":         "authentication",
	"session_end":    "authentication",

	"system": "system",
}

// logCategory is the Logs tab category of an event_type.
func logCategory(eventType string) string {
	if c, ok := logCategories[eventType]; ok {
		return c
	}
	return "system"
}

// derivedCategories are given to lines that don't name them: an untyped line
// carrying an SMTP 5xx or 4xx reply becomes a rejection or tempfail
// (categorizeLogEntry). Their text needn't contain the category's name.
var derivedCategories = map[string]bool{"rejection": true, "tempfail": true, "system": true}

// categoryNeedles is what a line must contain, lowercased, to possibly be in
// category: the names of its event types. nil means no cheap test is possible
// and every line is parsed. Before the categories had several types each, the
// pre-filter looked for the category's own name, which a message_received
// line doesn't contain.
func categoryNeedles(category string) []string {
	category = strings.ToLower(category)
	if category == "" || derivedCategories[category] {
		return nil
	}
	var needles []string
	for eventType, c := range logCategories {
		if c == category {
			needles = append(needles, `"event_type":"`+eventType+`"`)
		}
	}
	if len(needles) == 0 {
		// Not a category: nothing can match it, and the full check says so.
		return nil
	}
	return needles
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
