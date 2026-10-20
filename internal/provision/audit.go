package provision

import (
	"context"
	"log/slog"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// Audit records an administrative change. It always logs; with the mailbox
// admin API configured it also stores the entry in the mailbox's audit
// table, which is what the dashboard's audit page reads. The change has
// already been made when this is called, so a failure to store the entry is
// logged and returned for the caller to report, not to undo anything.
func (s *Service) Audit(ctx context.Context, e mailpolicy.AuditEntry) error {
	slog.Info("Mailbox administration", "actor", e.Actor, "source", e.Source, "client", e.Client, "action", e.Action, "target", e.Target, "detail", e.Detail)
	if s == nil || s.Mailbox == nil {
		return nil
	}
	if err := s.Mailbox.Audit(ctx, e); err != nil {
		slog.Error("Mailbox administration not recorded in the audit log", "actor", e.Actor, "action", e.Action, "target", e.Target, "error", err)
		return err
	}
	return nil
}
