package smtp

import (
	"strings"
	"testing"
)

func TestCommandSecurityAcceptsDSNRecipientParameters(t *testing.T) {
	manager := NewCommandSecurityManager(quietLogger())
	for _, args := range []string{
		"TO:<user@example.com> ORCPT=rfc822;old@example.net",
		"TO:<user@example.com> NOTIFY=FAILURE,DELAY",
		"TO:<user@example.com> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;old+2Btag@example.net",
		"TO:<user@example.com> ORCPT=rfc822;old+3Dtag@example.net NOTIFY=NEVER",
	} {
		t.Run(args, func(t *testing.T) {
			if err := manager.ValidateCommand(t.Context(), "RCPT "+args+"\r\n"); err != nil {
				t.Fatalf("valid DSN command rejected before dispatch: %v", err)
			}
		})
	}
	for _, args := range []string{
		"TO:<user@example.com> ORCPT=rfc822;bad+ZZ",
		"TO:<user@example.com> ORCPT=rfc822",
		"TO:<user@example.com> NOTIFY=NEVER,FAILURE",
		"TO:<user@example.com> NOTIFY=FAILURE NOTIFY=DELAY",
		"TO:<user@example.com> ORCPT=rfc822;a@example.net ORCPT=rfc822;b@example.net",
		"TO:<user@example.com> ORCPT=rfc822;a@example.net; DROP TABLE users",
		"TO:<user@example.com> ORCPT=rfc822;a@example.net\r\nMAIL FROM:<other@example.com>",
		"TO:<user@example.com> ORCPT=rfc822;a\x00@example.net",
		"TO:<user@example.com> UNKNOWN=value",
		"TO:<user@example.com>junk ORCPT=rfc822;a@example.net",
	} {
		t.Run(args, func(t *testing.T) {
			if err := manager.ValidateCommand(t.Context(), "RCPT "+args+"\r\n"); err == nil {
				t.Fatal("malformed or injected DSN command accepted")
			}
		})
	}
}

func TestDSNRecipientParametersReachSMTPDispatch(t *testing.T) {
	server := startDesyncTestServer(t)
	// A real socket exercises the security gate that direct DSN parser tests
	// bypassed, which is where valid extension parameters were refused.
	p := dialProbe(t, server.Addr().String())
	for _, command := range []string{
		"EHLO source.example.net",
		"MAIL FROM:<sender@example.net> SIZE=4035 BODY=7BIT",
		"RCPT TO:<user@example.com> ORCPT=rfc822;user@example.com NOTIFY=FAILURE,DELAY",
	} {
		if reply := p.cmd(command); !strings.HasPrefix(reply, "250") {
			t.Fatalf("%s: %s", command, reply)
		}
	}
	p.cmd("RSET")
	p.cmd("MAIL FROM:<sender@example.net>")
	if reply := p.cmd("RCPT TO:<user@example.com> ORCPT=rfc822;bad+ZZ"); !strings.HasPrefix(reply, "501") {
		t.Fatalf("malformed ORCPT was not rejected: %s", reply)
	}
}
