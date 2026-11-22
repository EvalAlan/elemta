package webmail

// Setting up a mail app from the address alone.
//
// Thunderbird reads an autoconfig file, which Caddy serves (the cloud
// Caddyfile). Outlook asks Autodiscover instead: it POSTs the address to
// /autodiscover/autodiscover.xml on the address's domain, on
// autodiscover.<domain>, or on the host an _autodiscover._tcp SRV record
// names, and takes the IMAP and SMTP settings from the answer.
//
// Apple's Mail has no lookup at all. What it takes is a configuration
// profile: a file the user downloads and installs, which adds the mail
// account, the calendar and the contacts in one go. The webmail makes one
// for the signed-in user. It carries no password; the device asks for it,
// so the file is harmless if it ends up somewhere else.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"text/template"
)

// hostNameRE is what a host may look like before it is put in a setup
// answer: the request's Host comes from the client.
var hostNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// setupHost is the host apps are told to connect to: the one they reached
// this server on, which is the name its certificate carries for them.
func setupHost(r *http.Request) (string, bool) {
	host := strings.ToLower(hostOnly(r.Host))
	return host, len(host) <= 253 && hostNameRE.MatchString(host)
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

const (
	autodiscoverOutlook = "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
)

// autodiscover is POST /autodiscover/autodiscover.xml.
func (s *Server) autodiscover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email  string `xml:"Request>EMailAddress"`
		Schema string `xml:"Request>AcceptableResponseSchema"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err == nil {
		err = xml.Unmarshal(body, &req)
	}
	host, hostOK := setupHost(r)
	addr, addrErr := mail.ParseAddress(strings.TrimSpace(req.Email))
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	// Only the Outlook schema: this server has no Exchange ActiveSync, which
	// is what phones asking for "mobilesync" want.
	if err != nil || !hostOK || addrErr != nil || addr.Address != strings.TrimSpace(req.Email) || len(addr.Address) > 254 ||
		(req.Schema != "" && req.Schema != autodiscoverOutlook) {
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response>
    <Error>
      <ErrorCode>600</ErrorCode>
      <Message>Invalid Request</Message>
      <DebugData />
    </Error>
  </Response>
</Autodiscover>
`)
		return
	}
	h, a := xmlText(host), xmlText(addr.Address)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="%s">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>%s</Server>
        <Port>993</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>%s</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>%s</Server>
        <Port>587</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>%s</LoginName>
        <SPA>off</SPA>
        <Encryption>TLS</Encryption>
        <AuthRequired>on</AuthRequired>
        <UsePOPAuth>off</UsePOPAuth>
        <SMTPLast>off</SMTPLast>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
`, autodiscoverOutlook, h, a, h, a)
}

// profileUUID is stable for one address and payload, so downloading the
// profile again and installing it replaces the old one instead of adding a
// second account.
func profileUUID(parts ...string) string {
	sum := sha256.Sum256([]byte("elemta-profile\x00" + strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50 // a name-based UUID
	b[8] = b[8]&0x3f | 0x80
	h := strings.ToUpper(hex.EncodeToString(b))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

type appleProfile struct {
	Address, Name, MailHost, DAVHost, DAVPath string
	DAVPort                                   string
	DAVSSL                                    bool
	ID                                        string
	UUID, MailUUID, CalUUID, CardUUID         string
}

var appleProfileTmpl = template.Must(template.New("profile").Funcs(template.FuncMap{"x": xmlText}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>{{x .Address}}</string>
  <key>PayloadDescription</key><string>Mail, calendar and contacts for {{x .Address}}. Your device asks for the password while installing.</string>
  <key>PayloadIdentifier</key><string>{{x .ID}}</string>
  <key>PayloadOrganization</key><string>{{x .MailHost}}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{{.UUID}}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadIdentifier</key><string>{{x .ID}}.mail</string>
      <key>PayloadUUID</key><string>{{.MailUUID}}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>Mail</string>
      <key>EmailAccountDescription</key><string>{{x .Address}}</string>
      <key>EmailAccountName</key><string>{{x .Name}}</string>
      <key>EmailAccountType</key><string>EmailTypeIMAP</string>
      <key>EmailAddress</key><string>{{x .Address}}</string>
      <key>IncomingMailServerHostName</key><string>{{x .MailHost}}</string>
      <key>IncomingMailServerPortNumber</key><integer>993</integer>
      <key>IncomingMailServerUseSSL</key><true/>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerUsername</key><string>{{x .Address}}</string>
      <key>OutgoingMailServerHostName</key><string>{{x .MailHost}}</string>
      <key>OutgoingMailServerPortNumber</key><integer>587</integer>
      <key>OutgoingMailServerUseSSL</key><true/>
      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>OutgoingMailServerUsername</key><string>{{x .Address}}</string>
      <key>OutgoingPasswordSameAsIncomingPassword</key><true/>
      <key>SMIMEEnabled</key><false/>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.caldav.account</string>
      <key>PayloadIdentifier</key><string>{{x .ID}}.caldav</string>
      <key>PayloadUUID</key><string>{{.CalUUID}}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>Calendar</string>
      <key>CalDAVAccountDescription</key><string>{{x .Address}}</string>
      <key>CalDAVHostName</key><string>{{x .DAVHost}}</string>
      <key>CalDAVPort</key><integer>{{.DAVPort}}</integer>
      <key>CalDAVPrincipalURL</key><string>{{x .DAVPath}}</string>
      <key>CalDAVUseSSL</key>{{if .DAVSSL}}<true/>{{else}}<false/>{{end}}
      <key>CalDAVUsername</key><string>{{x .Address}}</string>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.carddav.account</string>
      <key>PayloadIdentifier</key><string>{{x .ID}}.carddav</string>
      <key>PayloadUUID</key><string>{{.CardUUID}}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>Contacts</string>
      <key>CardDAVAccountDescription</key><string>{{x .Address}}</string>
      <key>CardDAVHostName</key><string>{{x .DAVHost}}</string>
      <key>CardDAVPort</key><integer>{{.DAVPort}}</integer>
      <key>CardDAVPrincipalURL</key><string>{{x .DAVPath}}</string>
      <key>CardDAVUseSSL</key>{{if .DAVSSL}}<true/>{{else}}<false/>{{end}}
      <key>CardDAVUsername</key><string>{{x .Address}}</string>
    </dict>
  </array>
</dict>
</plist>
`))

// appleProfileDownload is GET /settings/devices/apple.mobileconfig.
func (s *Server) appleProfileDownload(w http.ResponseWriter, r *http.Request, sess *Session) {
	if sess.AdminActor != "" {
		http.Error(w, "Not available during administrator access.", http.StatusForbidden)
		return
	}
	dav, err := url.Parse(s.davURL(r))
	if err != nil || dav.Hostname() == "" {
		s.fail(w, r, sess, fmt.Errorf("webmail: calendar address: %w", err))
		return
	}
	mailHost := s.mailHost(r)
	if !hostNameRE.MatchString(mailHost) {
		s.fail(w, r, sess, fmt.Errorf("webmail: mail host %q isn't a host name", mailHost))
		return
	}
	davSSL := dav.Scheme == "https"
	davPort := dav.Port()
	if davPort == "" {
		davPort = "80"
		if davSSL {
			davPort = "443"
		}
	}
	addr := strings.ToLower(sess.Address)
	name := s.prefs(r.Context(), sess).DisplayName
	if name == "" {
		name = addr
	}
	sum := sha256.Sum256([]byte(addr))
	p := appleProfile{
		Address: addr, Name: name, MailHost: mailHost, DAVHost: dav.Hostname(), DAVPath: dav.EscapedPath(), DAVPort: davPort, DAVSSL: davSSL,
		ID:       "net.elemta.profile." + hex.EncodeToString(sum[:8]),
		UUID:     profileUUID(addr, "profile"),
		MailUUID: profileUUID(addr, "mail"), CalUUID: profileUUID(addr, "caldav"), CardUUID: profileUUID(addr, "carddav"),
	}
	var buf bytes.Buffer
	if err := appleProfileTmpl.Execute(&buf, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+mailHost+`.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}
