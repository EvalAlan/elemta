package commands

import (
	"fmt"

	"github.com/busybox42/elemta/internal/version"
	"github.com/spf13/cobra"
)

var (
	// Version is the version of the CLI, set via ldflags or defaulting to package version.
	Version = version.Version
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display version information for the Elemta CLI`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Elemta CLI version %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
