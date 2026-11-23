package main

import (
	"log/slog"
	"os"

	"github.com/EvalAlan/elemta/cmd/elemta/commands"
	"github.com/EvalAlan/elemta/internal/logging"
	"github.com/EvalAlan/elemta/internal/runtimepaths"
	"github.com/spf13/cobra"
)

// services are the commands that run until stopped. Only they write the log
// file.
//
// Every command used to open it, because logging is set up here before Cobra
// runs anything. A command run once and done wrote "logging initialized" and
// whatever else it logged into the shared file, and on the dev server a
// timer runs `elemta abuse firewall-plan` and `firewall-report` in the admin
// container every 15 seconds: about 20,000 lines a day, a fifth of the file,
// which is what the admin console's Logs tab reads and what rotates at 25 MB.
// Those commands still log, to standard output, where the timer's journal or
// the person running them sees it.
var services = map[string]bool{"server": true, "web": true, "webmail": true, "mailbox": true, "mailbox-router": true}

// writesLogFile reports whether cmd is a service: one of services, directly
// under the root ("webmail reset-password" is a command run once).
func writesLogFile(cmd *cobra.Command) bool {
	return cmd != nil && cmd.HasParent() && !cmd.Parent().HasParent() && services[cmd.Name()]
}

func main() {
	// Logging is set up before Cobra runs the command, so that everything it
	// logs is formatted alike; services also write the file (writesLogFile).
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}
	// Provisioning output is consumed by scripts, and export-bodies writes an
	// archive to stdout. Diagnostics belong on stderr, including startup
	// logging before Cobra runs the command.
	command, _, findErr := commands.GetRootCmd().Find(os.Args[1:])
	scripted := false
	if findErr == nil {
		for c := command; c != nil; c = c.Parent() {
			if c.Name() == "provision" || c.Name() == "export-bodies" {
				scripted = true
				break
			}
		}
	}
	switch {
	case scripted:
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, logging.Options(nil))))
	case findErr == nil && writesLogFile(command):
		// The default file; the server switches to [logging] file once the
		// configuration is read.
		logging.InitializeLogging(logLevel, runtimepaths.Detect().LogFile)
	default:
		logging.InitializeLogging(logLevel, "")
	}

	commands.Execute()
}
