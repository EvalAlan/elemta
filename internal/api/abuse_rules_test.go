package api

import (
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
