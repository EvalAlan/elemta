// Package version provides the application version information.
package version

import (
	"fmt"
	"runtime/debug"
	"time"
)

// Version is the current application version.
// This is the single source of truth for version across all components.
//
// It defaults to a development value but is intended to be overridden at
// build time via linker flags, e.g.:
//
//	go build -ldflags "-X github.com/EvalAlan/elemta/internal/version.Version=v1.2.3"
//
// The release workflow (.github/workflows/release.yml) stamps this with the
// pushed git tag.
var Version = "0.1.0-dev"

// SourceURL is where the source code is published. The GPL entitles users
// to it, so the web interfaces link here from their copyright notice.
const SourceURL = "https://github.com/EvalAlan/elemta"

// copyrightHolder and firstYear open the copyright notice.
const (
	copyrightHolder = "Alan Denniston"
	firstYear       = 2025
)

// Copyright is the notice the web interfaces show, such as
// "© 2025–2026 Alan Denniston". The range ends at the year the binary was
// built, from the VCS stamp Go embeds, so it moves forward with each
// release and never needs editing. Builds without that stamp (from an
// archive, or with -buildvcs=false) end it at the current year.
func Copyright() string {
	return copyright(buildYear())
}

func copyright(last int) string {
	if last <= firstYear {
		return fmt.Sprintf("© %d %s", firstYear, copyrightHolder)
	}
	return fmt.Sprintf("© %d–%d %s", firstYear, last, copyrightHolder)
}

func buildYear() int {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.time" {
				if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
					return t.Year()
				}
			}
		}
	}
	return time.Now().Year()
}
