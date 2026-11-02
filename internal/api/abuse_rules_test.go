package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/config"
	"github.com/pelletier/go-toml/v2"
)

// Rules are written by the surgical TOML editor and read back as a policy; a
// value with quotes in it must survive both.
func TestRulesSurviveTheConfigurationFile(t *testing.T) {
	want := []abuse.Rule{
		{Action: abuse.ActionDeny, Direction: abuse.DirectionInbound, Value: "203.0.113.0/24", Protocols: "imap,pop3", Note: `said "stop"`},
		{Action: abuse.ActionAllow, Direction: abuse.DirectionOutbound, Value: "partner.example", Expires: "2027-01-02T03:04:05Z"},
	}
	doc, err := config.SetTOMLValue([]byte("[abuse]\nmode = \"enforce\"\n"), "abuse", "rules", ruleTables(want))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Abuse abuse.Policy `toml:"abuse"`
	}
	if err := toml.Unmarshal(doc, &got); err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	if len(got.Abuse.Rules) != 2 || got.Abuse.Rules[0] != want[0] || got.Abuse.Rules[1] != want[1] {
		t.Fatalf("rules = %+v", got.Abuse.Rules)
	}
}

func TestARuleCannotCutOffTheAdministrator(t *testing.T) {
	p := abuse.DefaultPolicy()
	p.Rules = []abuse.Rule{{Action: abuse.ActionDeny, Direction: abuse.DirectionInbound, Value: "203.0.113.0/24"}}
	if _, cut := rulesCutOff(p, "203.0.113.7:1234"); !cut {
		t.Error("a rule covering the administrator was allowed")
	}
	if _, cut := rulesCutOff(p, "198.51.100.1"); cut {
		t.Error("a rule on someone else was refused")
	}
	p.Rules[0].Protocols = "imap"
	if _, cut := rulesCutOff(p, "203.0.113.7"); cut {
		t.Error("a rule that doesn't cover the console was refused")
	}
}

// The startup move writes the rules, empties the allowlist and the access
// lists, and leaves everything else in the file alone.
func TestAdoptAbusePolicyRewritesTheOldLists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "elemta.toml")
	original := "hostname = \"test.example.com\"\n\n[access_control]\nenabled = true\ndeny_ips = [\"203.0.113.0/24\"]\nallow_ips = []\nallow_domains = []\ndeny_domains = [\"spam.example\"]\n\n[abuse]\nmode = \"enforce\"\nallowlist = [\"198.51.100.7\"]\n\n[queue]\nbackend = \"file\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: dir},
		&MainConfig{Hostname: "test.example.com", QueueDir: dir, QueueBackend: "file"}, dir, 0, path)
	if err != nil {
		t.Fatal(err)
	}
	p := abuse.Policy{Mode: abuse.ModeEnforce, Allowlist: []string{"198.51.100.7"}}.WithDefaults()
	rules, skipped := abuse.AccessControlRules(nil, []string{"203.0.113.0/24"}, nil, []string{"spam.example"})
	if len(skipped) > 0 {
		t.Fatalf("skipped %v", skipped)
	}
	p, _ = p.AddRules(rules)
	if err := server.AdoptAbusePolicy(p, true); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		AccessControl struct {
			DenyIPs     []string `toml:"deny_ips"`
			DenyDomains []string `toml:"deny_domains"`
		} `toml:"access_control"`
		Abuse abuse.Policy `toml:"abuse"`
		Queue struct {
			Backend string `toml:"backend"`
		} `toml:"queue"`
	}
	if err := toml.Unmarshal(doc, &got); err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	if len(got.AccessControl.DenyIPs)+len(got.AccessControl.DenyDomains)+len(got.Abuse.Allowlist) != 0 {
		t.Fatalf("old lists kept:\n%s", doc)
	}
	if len(got.Abuse.Rules) != 3 || got.Queue.Backend != "file" {
		t.Fatalf("rules %+v, queue %q\n%s", got.Abuse.Rules, got.Queue.Backend, doc)
	}
}
