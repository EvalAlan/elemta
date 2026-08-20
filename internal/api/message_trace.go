package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/EvalAlan/elemta/internal/runtimepaths"
)

// Message tracing: what happened to one message.
//
// "Where did this message go" is the question an MTA is asked most, and until
// now the answer was "grep the logs". The queue view only shows what is still
// queued, so a message that was delivered — the common case — disappeared from
// the interface entirely, and a message that was rejected never appeared in it
// at all.
//
// Nothing new is recorded to make this work. The events are already written
// with a message_id: accepted, each delivery attempt with the remote's reply,
// delivered, deferred, bounced. This assembles them into the order they
// happened and says what the outcome was.

const (
	// traceScanBytes bounds how far back a trace looks. Log files grow without
	// limit and a trace is an interactive request; reading a gigabyte to answer
	// one is a denial of service with extra steps.
	traceScanBytes = 8 * 1024 * 1024

	// maxTraceEvents caps a single message's timeline. A message that has been
	// retried for days can have hundreds of attempts, and rendering all of them
	// is neither useful nor kind to the browser.
	maxTraceEvents = 500

	// maxSearchResults bounds the grouped search.
	maxSearchResults = 100
)

// TraceEvent is one thing that happened to a message.
type TraceEvent struct {
	Time    string                 `json:"time"`
	Level   string                 `json:"level"`
	Event   string                 `json:"event,omitempty"`
	Summary string                 `json:"summary"`
	Detail  string                 `json:"detail,omitempty"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

// MessageTrace is a message's history plus where it stands now.
type MessageTrace struct {
	MessageID string       `json:"message_id"`
	From      string       `json:"from,omitempty"`
	To        []string     `json:"to,omitempty"`
	Subject   string       `json:"subject,omitempty"`
	Outcome   string       `json:"outcome"`
	Events    []TraceEvent `json:"events"`
	// InQueue is the message's current queue entry, when it is still queued.
	// A trace that only reads logs would say "deferred" about a message that
	// has since been delivered or deleted.
	InQueue interface{} `json:"in_queue,omitempty"`
	// Truncated says the scan stopped before the beginning of the log. "No
	// earlier events" and "we stopped looking" are different answers and an
	// operator deciding whether a message was ever received needs to know
	// which one they got.
	Truncated bool `json:"truncated"`
}

// handleTraceMessage returns one message's timeline.
func (s *Server) handleTraceMessage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	if id == "" {
		http.Error(w, "A message ID is required", http.StatusBadRequest)
		return
	}
	// An unbounded needle would match every line in the file and return the
	// whole log as one message's history.
	if len(id) < 6 {
		http.Error(w, "That message ID is too short to identify a message", http.StatusBadRequest)
		return
	}

	entries, truncated, err := scanLinkedIDs(id, maxTraceEvents)
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not read the log: %v", err), http.StatusServiceUnavailable)
		return
	}

	trace := buildTrace(id, entries)
	trace.Truncated = truncated

	// What the queue says now beats what the log said last.
	if s.queueMgr != nil {
		if msg, qErr := s.queueMgr.GetMessage(id); qErr == nil {
			trace.InQueue = msg
			trace.Outcome = "in queue"
		}
	}

	writeJSON(w, trace)
}

// handleSearchMessages finds recent messages by address, subject or ID.
//
// Tracing needs an ID, and an operator handling a complaint has an email
// address. This closes that gap: it groups recent log events by message so the
// answer to "what did we do with mail for this person" is one request.
func (s *Server) handleSearchMessages(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) < 3 {
		http.Error(w, "Enter at least 3 characters to search for", http.StatusBadRequest)
		return
	}

	entries, truncated, err := scanLogForNeedle(query, maxSearchResults*20)
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not read the log: %v", err), http.StatusServiceUnavailable)
		return
	}

	type summary struct {
		MessageID string   `json:"message_id"`
		From      string   `json:"from,omitempty"`
		To        []string `json:"to,omitempty"`
		Subject   string   `json:"subject,omitempty"`
		Outcome   string   `json:"outcome"`
		FirstSeen string   `json:"first_seen"`
		LastSeen  string   `json:"last_seen"`
		Events    int      `json:"events"`
	}

	// A message carries two identifiers, so grouping naively lists it twice —
	// once as accepted and once as delivered, which reads as two messages and
	// makes the search untrustworthy. The reception record names both, so
	// canonical() folds them onto one.
	canonical := map[string]string{}
	for _, e := range entries {
		msgID := stringField(e.Fields, "message_id")
		queueID := stringField(e.Fields, "queue_id")
		if msgID != "" && queueID != "" && msgID != queueID {
			// The queue id is the one that survives into delivery, so it is the
			// one worth showing and tracing from.
			canonical[msgID] = queueID
		}
	}

	byID := map[string][]MessageLog{}
	var order []string
	for _, e := range entries {
		id := stringField(e.Fields, "message_id", "queue_id")
		if id == "" {
			continue
		}
		if mapped, ok := canonical[id]; ok {
			id = mapped
		}
		if _, seen := byID[id]; !seen {
			order = append(order, id)
		}
		byID[id] = append(byID[id], e)
	}

	results := make([]summary, 0, len(order))
	for _, id := range order {
		t := buildTrace(id, byID[id])
		s := summary{
			MessageID: id,
			From:      t.From,
			To:        t.To,
			Subject:   t.Subject,
			Outcome:   t.Outcome,
			Events:    len(t.Events),
		}
		if len(t.Events) > 0 {
			s.FirstSeen = t.Events[0].Time
			s.LastSeen = t.Events[len(t.Events)-1].Time
		}
		results = append(results, s)
	}

	// Newest first: an operator searching is almost always asking about
	// something that just happened.
	sort.SliceStable(results, func(i, j int) bool { return results[i].LastSeen > results[j].LastSeen })
	if len(results) > maxSearchResults {
		results = results[:maxSearchResults]
		truncated = true
	}

	writeJSON(w, map[string]interface{}{
		"query":     query,
		"messages":  results,
		"count":     len(results),
		"truncated": truncated,
	})
}

// scanLinkedIDs follows a message across the identifiers it is known by.
//
// A message has two: the one the SMTP session gives it and the one the queue
// assigns. They are different values, and only the reception record carries
// both. So a trace started from either one finds that record, learns the other
// identifier, and scans again — otherwise tracing the session id shows a
// message accepted and never delivered, and tracing the queue id shows one
// delivered with no record of it arriving.
//
// Exactly one extra round: identifiers cannot chain further, and a loop here
// would be a way to make one request read the log repeatedly.
func scanLinkedIDs(id string, maxEntries int) ([]MessageLog, bool, error) {
	entries, truncated, err := scanLogForNeedle(id, maxEntries)
	if err != nil {
		return nil, false, err
	}

	linked := map[string]struct{}{}
	for _, e := range entries {
		for _, key := range []string{"message_id", "queue_id"} {
			if other := stringField(e.Fields, key); other != "" && other != id {
				linked[other] = struct{}{}
			}
		}
	}

	for other := range linked {
		more, moreTruncated, err := scanLogForNeedle(other, maxEntries)
		if err != nil {
			continue
		}
		truncated = truncated || moreTruncated
		entries = append(entries, more...)
	}

	return dedupeEvents(entries), truncated, nil
}

// dedupeEvents drops the records the linked scans found twice — the reception
// record matches on both identifiers, so it would otherwise appear in the
// timeline once for each.
func dedupeEvents(entries []MessageLog) []MessageLog {
	seen := make(map[string]struct{}, len(entries))
	out := entries[:0]
	for _, e := range entries {
		key := e.Time + "\x00" + e.Message + "\x00" + e.EventType
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

// buildTrace turns raw log entries into an ordered timeline.
func buildTrace(id string, entries []MessageLog) *MessageTrace {
	trace := &MessageTrace{MessageID: id, Outcome: "unknown", Events: []TraceEvent{}}

	// The log is append-only, so it is already chronological; sorting by the
	// timestamp keeps that true if entries ever arrive from more than one file.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time < entries[j].Time })

	for _, e := range entries {
		summary, detail := describeEvent(e)
		trace.Events = append(trace.Events, TraceEvent{
			Time:    e.Time,
			Level:   e.Level,
			Event:   e.EventType,
			Summary: summary,
			Detail:  detail,
			Fields:  e.Fields,
		})

		// Envelope details are taken from whichever event carries them; the
		// acceptance record has them, later attempts often do not.
		if trace.From == "" {
			trace.From = stringField(e.Fields, "from", "from_envelope", "sender")
		}
		if trace.Subject == "" {
			trace.Subject = stringField(e.Fields, "subject")
		}
		if len(trace.To) == 0 {
			trace.To = stringsField(e.Fields, "to", "to_envelope", "recipients")
		}

		if outcome := outcomeFor(e); outcome != "" {
			trace.Outcome = outcome
		}
	}

	if len(trace.Events) == 0 {
		trace.Outcome = "not found"
	}
	return trace
}

// describeEvent turns a log line into a phrase an operator can read, and pulls
// out the part they actually want — the remote server's reply, or the reason.
func describeEvent(e MessageLog) (summary, detail string) {
	detail = stringField(e.Fields, "error", "reason", "response", "smtp_response", "last_error", "message")

	switch e.EventType {
	case "message_accepted", "reception":
		summary = "Accepted for delivery"
		if q := stringField(e.Fields, "queue_type"); q != "" {
			summary += " into the " + q + " queue"
		}
	case "delivery":
		summary = "Delivered"
		if host := stringField(e.Fields, "delivery_host", "delivery_ip"); host != "" {
			summary += " to " + host
		}
		if method := stringField(e.Fields, "delivery_method"); method != "" {
			summary += " over " + method
		}
	case "deferral", "tempfail":
		summary = "Deferred, will retry"
	case "bounce":
		summary = "Bounced"
	case "rejection":
		summary = "Rejected"
	case "virus_detected":
		summary = "Virus detected"
	case "spam_detected":
		summary = "Classified as spam"
	case "policy":
		summary = "Policy applied"
	default:
		// Falling back to the log's own message keeps events this does not know
		// about visible, rather than dropping them from the history.
		summary = e.Message
	}

	if summary == detail {
		detail = ""
	}
	return summary, detail
}

// outcomeFor reports the standing of a message after an event, or "" when the
// event does not settle anything.
//
// Detection is not disposition. A message can be classified as spam and still
// be delivered — that is what reject_on_spam=false means, and it is the default
// — so virus_detected and spam_detected deliberately settle nothing. Reading
// them as an outcome made a trace report "refused" about a message that had
// been delivered, which is worse than reporting nothing at all.
func outcomeFor(e MessageLog) string {
	switch e.EventType {
	case "delivery":
		return "delivered"
	case "bounce":
		return "bounced"
	case "rejection":
		return "rejected"
	case "deferral", "tempfail":
		return "deferred"
	case "message_accepted", "reception":
		return "accepted"
	}
	if status := stringField(e.Fields, "status"); status != "" {
		return status
	}
	return ""
}

// scanLogForNeedle reads the tail of the log and returns the parsed lines that
// contain needle.
//
// The substring check runs before the JSON parse because the overwhelming
// majority of lines do not match, and parsing them all to discard them is where
// the time would go.
func scanLogForNeedle(needle string, maxEntries int) ([]MessageLog, bool, error) {
	paths := runtimepaths.Detect()
	candidates := []string{paths.LogFile, "/app/logs/elemta.log", "./logs/elemta.log"}

	var lastErr error
	for _, candidate := range candidates {
		if !isAllowedLogPath(candidate) {
			continue
		}
		entries, truncated, err := scanOneLog(candidate, needle, maxEntries)
		if err != nil {
			lastErr = err
			continue
		}
		return entries, truncated, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no readable log file")
	}
	return nil, false, lastErr
}

func scanOneLog(filename, needle string, maxEntries int) ([]MessageLog, bool, error) {
	// #nosec G304 -- path is constrained by the isAllowedLogPath allowlist
	file, err := os.Open(filename)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()

	stat, err := file.Stat()
	if err != nil {
		return nil, false, err
	}

	start := int64(0)
	truncated := false
	if stat.Size() > traceScanBytes {
		start = stat.Size() - traceScanBytes
		truncated = true
	}

	buf := make([]byte, stat.Size()-start)
	if _, err := file.ReadAt(buf, start); err != nil && len(buf) == 0 {
		return nil, false, err
	}

	lines := strings.Split(string(buf), "\n")
	// Starting mid-file leaves a partial first line, which is not a log entry.
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}

	entries := make([]MessageLog, 0, 16)
	for _, line := range lines {
		if !strings.Contains(line, needle) {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue // not a structured line
		}
		entries = append(entries, toMessageLog(raw))
		if len(entries) >= maxEntries {
			truncated = true
			break
		}
	}
	return entries, truncated, nil
}

// toMessageLog lifts the well-known keys out and keeps the rest as fields, so
// an event this code has never heard of still shows what it carried.
func toMessageLog(raw map[string]interface{}) MessageLog {
	entry := MessageLog{Fields: map[string]interface{}{}}
	for k, v := range raw {
		switch k {
		case "time":
			entry.Time, _ = v.(string)
		case "level":
			entry.Level, _ = v.(string)
		case "msg":
			entry.Message, _ = v.(string)
		case "event_type":
			entry.EventType, _ = v.(string)
		case "component":
			entry.Component, _ = v.(string)
		default:
			entry.Fields[k] = v
		}
	}
	return entry
}

// stringField returns the first of keys that holds a non-empty string.
func stringField(fields map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := fields[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// stringsField returns the first of keys that holds a list of strings, also
// accepting a bare string, since some events log a single recipient that way.
func stringsField(fields map[string]interface{}, keys ...string) []string {
	for _, k := range keys {
		v, ok := fields[k]
		if !ok {
			continue
		}
		switch typed := v.(type) {
		case []interface{}:
			out := make([]string, 0, len(typed))
			for _, item := range typed {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		case string:
			if typed != "" {
				return []string{typed}
			}
		}
	}
	return nil
}
