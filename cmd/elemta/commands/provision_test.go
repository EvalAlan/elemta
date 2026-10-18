package commands

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/provision"
)

type cliDirectory struct{}

func (cliDirectory) List(context.Context) ([]provision.Account, error) {
	return []provision.Account{{Address: "dana@example.com", Name: "Dana", Status: "active", Aliases: []string{}}}, nil
}
func (cliDirectory) Get(context.Context, string) (provision.Account, error) {
	return provision.Account{Address: "dana@example.com", Name: "Dana", Status: "active", Aliases: []string{}}, nil
}
func (cliDirectory) Create(context.Context, provision.Create) (provision.Account, error) {
	return provision.Account{}, provision.ErrUnavailable
}
func (cliDirectory) Update(context.Context, string, provision.Patch) (provision.Account, error) {
	return provision.Account{}, provision.ErrUnavailable
}
func (cliDirectory) Delete(context.Context, string) error { return provision.ErrUnavailable }
func (cliDirectory) Alias(context.Context, string, string, bool) (provision.Account, error) {
	return provision.Account{}, provision.ErrUnavailable
}
func TestProvisionCLIReadableAndJSON(t *testing.T) {
	for _, args := range [][]string{{"gaa"}, {"--json", "ga", "dana@example.com"}} {
		cmd := newProvisionCommand(func() (*provision.Service, error) { return &provision.Service{Directory: cliDirectory{}}, nil })
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "dana@example.com") {
			t.Fatal(out.String())
		}
		if args[0] == "--json" && !strings.Contains(out.String(), `"address"`) {
			t.Fatal("missing JSON output")
		}
	}
}
func TestProvisionCLIDeletionRequiresMatchingAddress(t *testing.T) {
	cmd := newProvisionCommand(func() (*provision.Service, error) { return &provision.Service{Directory: cliDirectory{}}, nil })
	cmd.SetArgs([]string{"da", "dana@example.com"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("deletion not protected: %v", err)
	}
}
