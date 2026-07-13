// Package version provides the application version information.
package version

// Version is the current application version.
// This is the single source of truth for version across all components.
//
// It defaults to a development value but is intended to be overridden at
// build time via linker flags, e.g.:
//
//	go build -ldflags "-X github.com/busybox42/elemta/internal/version.Version=v1.2.3"
//
// The release workflow (.github/workflows/release.yml) stamps this with the
// pushed git tag.
var Version = "0.1.0-dev"
