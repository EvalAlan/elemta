package queue

import (
	"context"
	"errors"
	"log/slog"
	"strings"
)

// SplitDeliveryHandler sends each recipient by the route its domain deserves:
// local domains to the mailbox server, everything else out over SMTP.
//
// The SMTP session already makes this distinction. At RCPT time it decides
// whether a recipient is in a local domain, and refuses to relay for anyone
// else unless they authenticated or came from an allowed network. Delivery then
// threw that away and pushed every message through one handler chosen once at
// startup, so a server could accept mail for both and only ever deliver it one
// way.
//
// This changes where accepted mail goes and nothing else. Whether a recipient is
// allowed at all stays entirely in the session's relay check — routing must
// never become authorization, because a router that decides who may send is one
// bug away from being an open relay.
type SplitDeliveryHandler struct {
	local        DeliveryHandler
	remote       DeliveryHandler
	localDomains map[string]struct{}
	logger       *slog.Logger
}

// NewSplitDeliveryHandler routes to local for the given domains and to remote
// for the rest.
func NewSplitDeliveryHandler(local, remote DeliveryHandler, localDomains []string, logger *slog.Logger) *SplitDeliveryHandler {
	if logger == nil {
		logger = slog.Default()
	}
	domains := make(map[string]struct{}, len(localDomains))
	for _, domain := range localDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			domains[domain] = struct{}{}
		}
	}
	return &SplitDeliveryHandler{
		local:        local,
		remote:       remote,
		localDomains: domains,
		logger:       logger.With("component", "split-delivery"),
	}
}

// isLocal reports whether a recipient belongs to a configured local domain.
func (h *SplitDeliveryHandler) isLocal(recipient string) bool {
	at := strings.LastIndex(recipient, "@")
	if at < 0 {
		// No domain to route on. Treating it as remote would put it in front of
		// a DNS lookup that cannot succeed; local delivery gives a definite
		// answer from the mailbox server instead.
		return true
	}
	_, ok := h.localDomains[strings.ToLower(strings.TrimSpace(recipient[at+1:]))]
	return ok
}

func (h *SplitDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata splits the envelope and delivers each part.
//
// A message addressed to both a local mailbox and an outside address is one
// message with two destinations, so it is delivered twice — once per route —
// and the per-recipient outcomes are merged. That matters because the queue
// drops delivered recipients before a retry: without accurate per-recipient
// results, a remote deferral would redeliver to the local mailbox on every
// attempt and the recipient would receive the message repeatedly.
func (h *SplitDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	local, remote := h.partition(msg.To)

	// A message with only one kind of recipient goes straight through the
	// handler it belongs to. Nothing is wrapped, so the common case behaves
	// exactly as it did before routing existed.
	switch {
	case len(remote) == 0:
		return h.deliverVia(ctx, h.local, msg, content, local, "local")
	case len(local) == 0:
		return h.deliverVia(ctx, h.remote, msg, content, remote, "remote")
	}

	h.logger.InfoContext(ctx, "Message split across routes",
		"message_id", msg.ID, "local_recipients", len(local), "remote_recipients", len(remote))

	localResult, localErr := h.deliverVia(ctx, h.local, msg, content, local, "local")
	remoteResult, remoteErr := h.deliverVia(ctx, h.remote, msg, content, remote, "remote")

	merged := &DeliveryResult{
		Success:      localErr == nil && remoteErr == nil,
		DeliveryTime: localResult.DeliveryTime,
	}
	if merged.DeliveryTime.IsZero() {
		merged.DeliveryTime = remoteResult.DeliveryTime
	}
	// The remote hop is the interesting one to report: local delivery is always
	// the same mailbox server, so its address tells an operator nothing.
	merged.DeliveryHost = remoteResult.DeliveryHost
	merged.DeliveryIP = remoteResult.DeliveryIP
	merged.ResponseMessage = joinResponses(localResult.ResponseMessage, remoteResult.ResponseMessage)
	merged.RecipientOutcomes = append(
		append([]RecipientOutcome{}, localResult.RecipientOutcomes...),
		remoteResult.RecipientOutcomes...)
	merged.Error = errors.Join(localErr, remoteErr)

	return merged, merged.Error
}

// deliverVia sends one subset of the envelope through one handler.
func (h *SplitDeliveryHandler) deliverVia(ctx context.Context, handler DeliveryHandler, msg Message, content []byte, recipients []string, route string) (*DeliveryResult, error) {
	if handler == nil {
		// Configured for a route with nothing behind it. Temporary rather than
		// permanent: the mail is fine, the server is not, and bouncing it would
		// destroy deliverable messages over a configuration mistake.
		err := errors.New("no delivery handler configured for the " + route + " route")
		return &DeliveryResult{
			Error:             err,
			RecipientOutcomes: outcomesFor(recipients, RecipientTemporaryFailure, err.Error(), route),
		}, err
	}

	part := msg
	part.To = recipients
	result, err := handler.DeliverMessageWithMetadata(ctx, part, content)
	if result == nil {
		result = &DeliveryResult{Error: err}
	}
	// Record which way each recipient went, for tracing. A handler that already
	// said something more specific keeps it.
	for i := range result.RecipientOutcomes {
		if result.RecipientOutcomes[i].Route == "" {
			result.RecipientOutcomes[i].Route = route
		}
	}
	return result, err
}

// partition splits recipients by route, preserving order and duplicates. Both
// matter: a duplicate envelope recipient is legal, and the queue matches
// outcomes to recipients by occurrence.
func (h *SplitDeliveryHandler) partition(recipients []string) (local, remote []string) {
	for _, recipient := range recipients {
		if h.isLocal(recipient) {
			local = append(local, recipient)
			continue
		}
		remote = append(remote, recipient)
	}
	return local, remote
}

// outcomesFor marks a whole group with one status.
func outcomesFor(recipients []string, status RecipientDeliveryStatus, diagnostic, route string) []RecipientOutcome {
	out := make([]RecipientOutcome, 0, len(recipients))
	for _, recipient := range recipients {
		out = append(out, RecipientOutcome{
			Recipient: recipient, Status: status, Diagnostic: diagnostic, Route: route,
		})
	}
	return out
}

func joinResponses(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// GetFailedQueueRetentionHours reports the retention both routes share.
func (h *SplitDeliveryHandler) GetFailedQueueRetentionHours() int {
	if h.local != nil {
		return h.local.GetFailedQueueRetentionHours()
	}
	if h.remote != nil {
		return h.remote.GetFailedQueueRetentionHours()
	}
	return 0
}
