package main

import (
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
	logging.InitializeLogging(logLevel)

	commands.Execute()
}
