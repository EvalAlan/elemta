package webmail

import (
	"net/url"
	"strings"
	"testing"
)

func protocolHarness(t *testing.T, security *fakeSecurity) (*harness, string) {
	t.Helper()
	h := newSecurityHarness(t, security)
	return h, h.login()
}

func TestProtocolChoices(t *testing.T) {
	security := &fakeSecurity{protocolChoices: []protocolChoice{{Protocol: "imap", Allowed: true, On: true}, {Protocol: "pop3", Allowed: true}}}
	h, csrf := protocolHarness(t, security)
	_, page := h.get("/settings/devices")
	for _, want := range []string{"Mail app access", `name="protocol" value="imap"`, `name="protocol" value="pop3"`, "Turn off", "Turn on", ">993<"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(page, ">110<") {
		t.Error("lists POP3 server settings with POP3 off")
	}
	resp := h.post("/settings/protocols", url.Values{"csrf": {csrf}, "protocol": {"imap"}, "on": {"0"}})
	if resp.StatusCode != 303 || len(security.protocolCalls) != 1 || security.protocolCalls[0]["protocol"] != "imap" || security.protocolCalls[0]["on"] != false {
		t.Fatalf("status %d, calls %v", resp.StatusCode, security.protocolCalls)
	}
}

// What a class refuses is said plainly, with nothing to press.
func TestClassRefusalOffersNoChoice(t *testing.T) {
	h, _ := protocolHarness(t, &fakeSecurity{protocolChoices: []protocolChoice{{Protocol: "imap", Allowed: true, On: true}, {Protocol: "pop3"}}})
	_, page := h.get("/settings/devices")
	if !strings.Contains(page, "Turned off by your administrator") {
		t.Error("doesn't explain")
	}
	if strings.Contains(page, `name="protocol" value="pop3"`) {
		t.Error("offers a toggle the class refuses")
	}
}
