package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/smtp"
	toml "github.com/pelletier/go-toml/v2"
)

// shippedConfigs are the configurations people start from: the release
// tarball's starter config and the Compose stack's template. The loader
// ignores unknown keys, so a renamed or misplaced setting there would be
// dropped without a word; here it fails the build instead. Because CI checks
// out only what git tracks, a file that .gitignore swallowed (as happened to
// the release config) fails here too, rather than in the Release workflow.
var shippedConfigs = []string{
	"../../packaging/release/elemta.toml",
	"../../config/elemta.toml",
}

func TestShippedConfigsHaveNoUnknownKeys(t *testing.T) {
	for _, path := range shippedConfigs {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		cfg := DefaultConfig()
		cfg.TLS = &smtp.TLSConfig{}
		dec := toml.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		err = dec.Decode(cfg)
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			var keys []string
			for _, e := range strict.Errors {
				keys = append(keys, strings.Join(e.Key(), "."))
			}
			t.Errorf("%s: keys the server would ignore: %s", path, strings.Join(keys, ", "))
		} else if err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

// The release starter config must load as a user would run it: from the
// unpacked directory, at mode 600, with its relative paths.
func TestReleaseStarterConfigLoads(t *testing.T) {
	b, err := os.ReadFile("../../packaging/release/elemta.toml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "elemta.toml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err != nil {
		t.Fatalf("the release starter config doesn't load: %v", err)
	}
}
