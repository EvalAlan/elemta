package webmail

import (
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"testing"
)

func autodiscoverRequest(email, schema string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>` + email + `</EMailAddress>
    <AcceptableResponseSchema>` + schema + `</AcceptableResponseSchema>
  </Request>
</Autodiscover>`
}

func postAutodiscover(t *testing.T, h *harness, path, host, body string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Content-Type", "text/xml")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/xml") {
		t.Fatalf("%s = %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if err := xml.Unmarshal(b, new(struct{})); err != nil {
		t.Fatalf("not XML: %v\n%s", err, b)
	}
	return string(b)
}

func TestAutodiscover(t *testing.T) {
	h := newHarness(t)
	got := postAutodiscover(t, h, "/autodiscover/autodiscover.xml", "mail.example.com", autodiscoverRequest("dana@example.com", autodiscoverOutlook))
	for _, want := range []string{
		"<Type>IMAP</Type>", "<Server>mail.example.com</Server>", "<Port>993</Port>", "<SSL>on</SSL>",
		"<Type>SMTP</Type>", "<Port>587</Port>", "<Encryption>TLS</Encryption>", "<LoginName>dana@example.com</LoginName>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("answer lacks %s:\n%s", want, got)
		}
	}
	// Outlook also asks with capitals, and sometimes without a schema.
	if got := postAutodiscover(t, h, "/Autodiscover/Autodiscover.xml", "mail.example.com", autodiscoverRequest("dana@example.com", "")); !strings.Contains(got, "<Type>IMAP</Type>") {
		t.Errorf("capitalised path:\n%s", got)
	}
	for name, body := range map[string]string{
		"ActiveSync":    autodiscoverRequest("dana@example.com", "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006"),
		"not an email":  autodiscoverRequest("dana", autodiscoverOutlook),
		"display name":  autodiscoverRequest("Dana &lt;dana@example.com&gt;", autodiscoverOutlook),
		"markup inside": autodiscoverRequest("dana@example.com</EMailAddress><x>", autodiscoverOutlook),
		"not XML":       "hello",
	} {
		if got := postAutodiscover(t, h, "/autodiscover/autodiscover.xml", "mail.example.com", body); !strings.Contains(got, "<ErrorCode>600</ErrorCode>") || strings.Contains(got, "<Protocol>") {
			t.Errorf("%s: %s", name, got)
		}
	}
	// A Host that isn't a host name doesn't get echoed into the answer.
	if got := postAutodiscover(t, h, "/autodiscover/autodiscover.xml", "evil<x>", autodiscoverRequest("dana@example.com", autodiscoverOutlook)); !strings.Contains(got, "<ErrorCode>600</ErrorCode>") {
		t.Errorf("bad host: %s", got)
	}
}

func TestAppleProfile(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.get("/settings/devices/apple.mobileconfig"); resp.StatusCode != http.StatusFound {
		t.Fatalf("signed out = %d", resp.StatusCode)
	}
	h.login()
	_, page := h.get("/settings/devices")
	if !strings.Contains(page, `href="/settings/devices/apple.mobileconfig"`) {
		t.Fatal("no Apple setup button on the Mail apps page")
	}
	resp, first := h.get("/settings/devices/apple.mobileconfig")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment; filename=") {
		t.Fatalf("download = %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"))
	}
	if err := xml.Unmarshal([]byte(first), new(struct{})); err != nil {
		t.Fatalf("profile isn't XML: %v", err)
	}
	for _, want := range []string{
		"<string>com.apple.mail.managed</string>", "<string>com.apple.caldav.account</string>", "<string>com.apple.carddav.account</string>",
		"<key>IncomingMailServerPortNumber</key><integer>993</integer>", "<key>OutgoingMailServerPortNumber</key><integer>587</integer>",
		"<key>CalDAVPrincipalURL</key><string>/dav/</string>",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("profile lacks %s", want)
		}
	}
	if strings.Contains(first, "secret") || strings.Contains(first, "Password</key><string>") {
		t.Error("the profile carries a password")
	}
	// The same download each time, so installing it again replaces it.
	if _, again := h.get("/settings/devices/apple.mobileconfig"); again != first {
		t.Error("profile changes between downloads")
	}
}

func TestProfileUUID(t *testing.T) {
	a, b := profileUUID("dana@example.com", "mail"), profileUUID("dana@example.com", "caldav")
	if a == b || len(a) != 36 || a[14] != '5' || !strings.ContainsAny(a[19:20], "89AB") || a != profileUUID("dana@example.com", "mail") {
		t.Errorf("uuids %s %s", a, b)
	}
}
