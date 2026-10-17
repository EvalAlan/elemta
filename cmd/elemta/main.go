package main

import (
	"log/slog"
	"os"

	"github.com/EvalAlan/elemta/cmd/elemta/commands"
	"github.com/EvalAlan/elemta/internal/logging"
)

func main() {
	// Initialize logging very early to ensure all components write to both stdout and file
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}
	// Provisioning output is consumed by scripts. Its diagnostics belong on
	// stderr, including startup logging before Cobra runs the command.
	command, _, findErr := commands.GetRootCmd().Find(os.Args[1:])
	provisioning := false
	if findErr == nil {
		for c := command; c != nil; c = c.Parent() {
			if c.Name() == "provision" {
				provisioning = true
				break
			}
		}
	}
	if provisioning {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	} else {
		logging.InitializeLogging(logLevel)
	}

	commands.Execute()
}
