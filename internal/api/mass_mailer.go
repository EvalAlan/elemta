package api

import (
	"errors"
	"log/slog"

	"github.com/busybox42/elemta/internal/campaign"
	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/suppression"
)

// Turning the mass mailer on and off at runtime.
//
// The campaign store and runner live in this process, not in the SMTP server,
// so unlike the scanners this toggle does not need a restart to take effect.
// Reporting "restart required" for something that could have been done now
// teaches operators to restart for changes that do not need it.

// massMailer returns the campaign store and runner, or nils when the feature is
// off. Callers must not hold on to the values across a request: the plugin
// toggle replaces them.
func (s *Server) massMailer() (*campaign.Store, *campaign.Runner) {
	s.massMailerMu.RLock()
	defer s.massMailerMu.RUnlock()
	return s.campaigns, s.campaignRunner
}

// setMassMailerEnabled builds or discards the campaign machinery.
//
// Disabling is refused while a campaign is running. Dropping the store would
// abandon a partly-sent campaign: the messages already handed to the queue go
// out, the rest never do, and the record of which was which disappears with the
// store. Pausing or cancelling first makes that choice the operator's.
func (s *Server) setMassMailerEnabled(enabled bool) error {
	s.massMailerMu.Lock()
	defer s.massMailerMu.Unlock()

	if !enabled {
		if s.campaigns != nil {
			for _, c := range s.campaigns.List() {
				if c.State == campaign.StateRunning {
					return errors.New("a campaign is still sending; pause or cancel it before turning the mass mailer off")
				}
			}
		}
		s.campaigns = nil
		s.campaignRunner = nil
		return nil
	}

	if s.campaigns != nil {
		return nil // already on; keep the campaigns that exist
	}
	s.campaigns = campaign.NewStore()
	s.campaignRunner = campaign.NewRunner(
		s.campaigns, s.queueMgr, s.massMailerHostname(),
		slog.Default().With("component", "mass-mailer"),
	)

	// A campaign asks the suppression list before every recipient, so a run
	// started tomorrow does not mail the addresses that bounced today.
	if s.suppressed != nil {
		s.campaignRunner.SetSuppressionList(s.suppressed)
	}

	// A development stack gets a worked example, so the Mass Mailer does not
	// open on an empty list that explains nothing. Draft, local recipients,
	// never started — see demo_campaign.go.
	if seedDemoCampaign(s.campaigns, s.massMailerHostname()) {
		slog.Default().Info("Added the demo campaign",
			"component", "mass-mailer",
			"note", "a draft addressed to this stack's own mailboxes; it is not sent")
	}
	return nil
}

// suppressionStore returns the list, or nil when it could not be opened.
func (s *Server) suppressionStore() *suppression.Store {
	return s.suppressed
}

func (s *Server) massMailerHostname() string {
	if s.mainConfig != nil && s.mainConfig.Hostname != "" {
		return s.mainConfig.Hostname
	}
	return "localhost"
}

// pluginEnabled reports a plugin's current state, so an update that carries
// only settings does not have to restate it.
func (s *Server) pluginEnabled(plugin string) bool {
	if s.mainConfig == nil {
		return false
	}
	switch plugin {
	case "rate_limiter":
		if rc, ok := s.mainConfig.RateLimiterPluginConfig.(*config.RateLimiterPluginConfig); ok && rc != nil {
			return rc.Enabled
		}
	case "clamav":
		if av := s.mainConfig.Antivirus; av != nil {
			return av.Enabled
		}
	case "rspamd":
		if as := s.mainConfig.Antispam; as != nil {
			return as.Enabled
		}
	case "access_control":
		if ac := s.mainConfig.AccessControl; ac != nil {
			return ac.Enabled
		}
	case "rbl":
		if r := s.mainConfig.RBL; r != nil {
			return r.Enabled
		}
	case "mass_mailer":
		if mm := s.mainConfig.MassMailer; mm != nil {
			return mm.Enabled
		}
	case "spf":
		return s.mainConfig.SPF != nil && s.mainConfig.SPF.Enabled
	case "dkim":
		return s.mainConfig.DKIM != nil && s.mainConfig.DKIM.Enabled
	case "arc":
		return s.mainConfig.ARC != nil && s.mainConfig.ARC.Enabled
	case "dmarc":
		return s.mainConfig.DMARC != nil && s.mainConfig.DMARC.Enabled
	}
	return false
}
