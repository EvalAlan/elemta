package mailbox

// Sieve at delivery time.
//
// When an account has an active script, LMTP delivery runs it and applies
// what it asks for: keep, fileinto (with flags, :copy and :create),
// discard, redirect, reject and vacation. A script that fails to compile or
// run falls back to keeping the message, so a bad filter can't lose mail.
//
// LMTP may retry a delivery whose outcome was uncertain. Each store gets
// its own delivery token (the queue's ENVID plus the target), so a retry
// finds the earlier stores instead of duplicating them. Redirect-only rules
// retain a local copy before forwarding; completed redirects are recorded
// after submission, so a retry after a crash can resend but cannot silently
// acknowledge a lost local message.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	sieve "github.com/EvalAlan/elemta/internal/sievefork"
	"github.com/EvalAlan/elemta/internal/sievefork/interp"
	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"github.com/emersion/go-smtp"
)

// redirectHeader marks mail this service redirected, so a redirect loop
// between two accounts stops at the second hop.
const redirectHeader = "X-Elemta-Sieve-Redirected-By"

// sieveCache keeps compiled scripts by account, valid while the script's
// update time is unchanged.
type sieveCache struct {
	mu      sync.Mutex
	entries map[string]cachedScript
}

type cachedScript struct {
	updated time.Time
	script  *sieve.Script
	err     error
}

const maxCachedScripts = 10000

func (c *sieveCache) get(account string, s SieveScript) (*sieve.Script, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]cachedScript{}
	}
	if e, ok := c.entries[account]; ok && e.updated.Equal(s.Updated) {
		return e.script, e.err
	}
	if len(c.entries) >= maxCachedScripts {
		c.entries = map[string]cachedScript{} // cheap bound; scripts recompile fast
	}
	script, err := compileSieve(s.Script)
	c.entries[account] = cachedScript{updated: s.Updated, script: script, err: err}
	return script, err
}

func compileSieve(text string) (*sieve.Script, error) {
	opts := sieve.DefaultOptions()
	opts.Interp.MaxRedirects = 4
	return sieve.Load(strings.NewReader(text), opts)
}

// sieveMessage gives the interpreter decoded header values (RFC 5228
// 2.7.2) and the body for the body extension.
type sieveMessage struct {
	interp.MessageStatic
	header gomail.Header
}

func (m sieveMessage) HeaderGet(key string) ([]string, error) {
	var out []string
	fields := m.header.FieldsByKey(key)
	for fields.Next() {
		v, err := fields.Text()
		if err != nil {
			v = fields.Value()
		}
		out = append(out, v)
	}
	return out, nil
}

type redirectPolicy struct{ max int }

func (p redirectPolicy) RedirectAllowed(_ context.Context, d *interp.RuntimeData, _ string) (bool, error) {
	n := 0
	for _, a := range d.AppliedActions {
		if _, ok := a.(interp.ActionRedirect); ok {
			n++
		}
	}
	return n < p.max, nil
}

// delivery is one recipient's copy of an incoming message.
type delivery struct {
	account Account
	from    string // envelope sender, "" for bounces
	rcpt    string // the address it was delivered to
	raw     []byte
	token   string // retry key, "" when the client gave none
}

func storeToken(token, target string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token + "\x00" + target))
	return hex.EncodeToString(sum[:])
}

// deliver stores one recipient's copy, running their Sieve script.
func (s *Service) deliver(ctx context.Context, d delivery) error {
	script, err := s.engine.ActiveScript(ctx, d.account.ID)
	if errors.Is(err, ErrNotFound) {
		_, err = s.engine.Append(ctx, d.account.ID, "INBOX", d.raw, nil, time.Now(), d.token)
		return err
	}
	if err != nil {
		return err
	}
	actions := s.runSieve(ctx, d, script)
	return s.applyActions(ctx, d, actions)
}

// runSieve runs the script and returns its actions, or a plain keep when
// it can't be run.
func (s *Service) runSieve(ctx context.Context, d delivery, stored SieveScript) []interp.AppliedAction {
	keep := []interp.AppliedAction{interp.ActionKeep{Implicit: true}}
	compiled, err := s.sieve.get(d.account.ID, stored)
	if err != nil {
		s.log.Warn("sieve script doesn't compile; keeping mail", "account", d.account.ID, "script", stored.Name, "error", err)
		return keep
	}
	header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(d.raw)))
	if err != nil {
		header = textproto.Header{}
	}
	msg := sieveMessage{
		MessageStatic: interp.MessageStatic{Size: len(d.raw), RawMessage: d.raw},
		header:        gomail.Header{Header: gomessage.Header{Header: header}},
	}
	env := interp.EnvelopeStatic{From: d.from, To: d.rcpt}
	rd := sieve.NewRuntimeData(compiled, redirectPolicy{max: s.cfg.Sieve.MaxRedirects}, env, msg)
	rd.Location = time.Local
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := compiled.Execute(runCtx, rd); err != nil {
		s.log.Warn("sieve script failed; keeping mail", "account", d.account.ID, "script", stored.Name, "error", err)
		return keep
	}
	return rd.AppliedActions
}

func (s *Service) applyActions(ctx context.Context, d delivery, actions []interp.AppliedAction) error {
	for _, a := range actions {
		switch a := a.(type) {
		case interp.ActionReject:
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: oneLine(a.Reason)}
		case interp.ActionEReject:
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: oneLine(a.Reason)}
		}
	}
	// Stores first: a failure there is retried by the queue, and side
	// effects only follow mail that was safely stored.
	stored := map[string]bool{}
	for _, a := range actions {
		switch a := a.(type) {
		case interp.ActionKeep:
			if err := s.store(ctx, d, "INBOX", a.Flags, false, stored); err != nil {
				return err
			}
		case interp.ActionFileInto:
			if err := s.store(ctx, d, a.Mailbox, a.Flags, a.Create, stored); err != nil {
				return err
			}
		}
	}
	// A redirect-only rule must leave a durable local disposition before
	// submission. This also gives the user a recoverable copy if a submission
	// acknowledgement is ambiguous and the upstream delivery is retried.
	redirect, retained := false, false
	for _, action := range actions {
		switch action.(type) {
		case interp.ActionRedirect:
			redirect = true
		case interp.ActionKeep, interp.ActionFileInto:
			retained = true
		}
	}
	if redirect && !retained {
		if err := s.store(ctx, d, "INBOX", nil, false, stored); err != nil {
			return err
		}
	}
	for _, a := range actions {
		switch a := a.(type) {
		case interp.ActionRedirect:
			if err := s.redirect(ctx, d, a.Address); err != nil {
				return err
			}
		case interp.ActionVacation:
			if err := s.vacation(ctx, d, a); err != nil {
				s.log.Warn("sieve vacation reply failed", "account", d.account.ID, "error", err)
			}
		}
	}
	return nil
}

// store files the message, once per folder. A missing folder is created
// for :create; otherwise the message goes to INBOX, as RFC 5228 requires
// when fileinto can't be done.
func (s *Service) store(ctx context.Context, d delivery, folder string, flags interp.Flags, create bool, done map[string]bool) error {
	if folder == "" {
		folder = "INBOX"
	}
	if _, err := s.engine.Folder(ctx, d.account.ID, folder); errors.Is(err, ErrNotFound) {
		if !create || !validMailbox(folder) {
			s.log.Info("sieve fileinto target missing; delivering to INBOX", "account", d.account.ID, "folder", folder)
			folder = "INBOX"
		} else if err := s.engine.Create(ctx, d.account.ID, folder); err != nil && !errors.Is(err, ErrExists) {
			return err
		}
	} else if err != nil {
		return err
	}
	key := canonicalMailbox(folder)
	if done[key] {
		return nil
	}
	done[key] = true
	_, err := s.engine.Append(ctx, d.account.ID, folder, d.raw, flags, time.Now(), storeToken(d.token, key))
	return err
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" {
		s = "Rejected by the recipient's filter"
	}
	return s
}

// ---- redirect ---------------------------------------------------------------

func (s *Service) redirect(ctx context.Context, d delivery, to string) error {
	addr, err := mail.ParseAddress(to)
	if err != nil {
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Forwarding address is invalid"}
	}
	target := strings.ToLower(addr.Address)
	if bytes.Contains(bytes.ToLower(headerBlock(d.raw)), []byte(strings.ToLower(redirectHeader+": "+d.rcpt))) {
		s.log.Info("sieve redirect loop stopped", "account", d.account.ID, "address", target)
		return s.store(ctx, d, "INBOX", nil, false, map[string]bool{})
	}
	if s.cfg.Sieve.SubmitAddr == "" {
		s.log.Warn("sieve redirect needs sieve.submit_addr; not sent", "account", d.account.ID)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Forwarding temporarily unavailable"}
	}
	key := "redirect-v2:" + sum(d.token+"\x00"+checksumOf(d.raw)) + ":" + target
	sent, err := s.engine.redirectSent(ctx, d.account.ID, key)
	if err != nil || sent {
		return err
	}
	msg := append([]byte(redirectHeader+": "+d.rcpt+"\r\n"), d.raw...)
	if err := s.submit(ctx, d.from, []string{target}, msg); err != nil {
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Forwarding temporarily unavailable"}
	}
	_, err = s.engine.claimSent(ctx, d.account.ID, key, 7*24*time.Hour)
	return err
}

func headerBlock(raw []byte) []byte {
	if end := headerEnd(raw); end >= 0 {
		return raw[:end]
	}
	return raw
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16])
}

func checksumOf(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// ---- vacation (RFC 5230, RFC 3834) ------------------------------------------

// automatedSender matches envelope senders that must never get an
// automatic reply (RFC 5230 4.6).
var automatedSender = regexp.MustCompile(`(?i)^(mailer-daemon|postmaster|listserv|majordomo|owner-.*|.*-request|.*-bounces?|.*-owner|no-?reply|do-?not-?reply|bounce.*)$`)

func (s *Service) vacation(ctx context.Context, d delivery, v interp.ActionVacation) error {
	if s.cfg.Sieve.SubmitAddr == "" {
		return errors.New("sieve.submit_addr isn't set")
	}
	sender, err := mail.ParseAddress(d.from)
	if d.from == "" || err != nil {
		return nil // a bounce, or nobody to answer
	}
	local, _, _ := strings.Cut(sender.Address, "@")
	if automatedSender.MatchString(local) {
		return nil
	}
	header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(d.raw)))
	if err != nil {
		return nil
	}
	mh := gomail.Header{Header: gomessage.Header{Header: header}}
	if as := strings.ToLower(strings.TrimSpace(header.Get("Auto-Submitted"))); as != "" && as != "no" {
		return nil
	}
	if header.Has("List-Id") || header.Has("List-Unsubscribe") || header.Has("List-Post") {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(header.Get("Precedence"))) {
	case "bulk", "list", "junk":
		return nil
	}
	// Only answer mail addressed to the user directly (RFC 5230 4.5).
	mine := map[string]bool{strings.ToLower(d.rcpt): true, strings.ToLower(d.account.Address): true}
	for _, a := range v.Addresses {
		if p, err := mail.ParseAddress(a); err == nil {
			mine[strings.ToLower(p.Address)] = true
		} else {
			mine[strings.ToLower(strings.TrimSpace(a))] = true
		}
	}
	if mine[strings.ToLower(sender.Address)] {
		return nil // never answer yourself
	}
	addressed := false
	for _, field := range []string{"To", "Cc", "Bcc", "Resent-To", "Resent-Cc", "Resent-Bcc"} {
		list, _ := mh.AddressList(field)
		for _, a := range list {
			if mine[strings.ToLower(a.Address)] {
				addressed = true
			}
		}
	}
	if !addressed {
		return nil
	}
	period := v.Period
	maxPeriod := time.Duration(s.cfg.Sieve.VacationMaxDays) * 24 * time.Hour
	if period < time.Hour {
		period = time.Hour
	}
	if period > maxPeriod {
		period = maxPeriod
	}
	key := "vacation:" + sum(v.Handle) + ":" + strings.ToLower(sender.Address)
	ok, err := s.engine.claimSent(ctx, d.account.ID, key, period)
	if err != nil || !ok {
		return err
	}
	reply, err := s.vacationReply(d, mh, v)
	if err != nil {
		s.engine.releaseSent(ctx, d.account.ID, key)
		return err
	}
	// The null sender, so a reply that bounces can't start a loop.
	if err := s.submit(ctx, "", []string{sender.Address}, reply); err != nil {
		s.engine.releaseSent(ctx, d.account.ID, key)
		return err
	}
	return nil
}

func (s *Service) vacationReply(d delivery, orig gomail.Header, v interp.ActionVacation) ([]byte, error) {
	var h gomail.Header
	from := []*gomail.Address{{Address: d.rcpt}}
	if v.From != "" {
		if list, err := gomail.ParseAddressList(v.From); err == nil && len(list) > 0 {
			from = list[:1]
		}
	}
	h.SetAddressList("From", from)
	sender, _ := gomail.ParseAddress(d.from)
	h.SetAddressList("To", []*gomail.Address{sender})
	subject := v.Subject
	if subject == "" {
		origSubject, _ := orig.Subject()
		subject = "Auto: " + origSubject
	}
	h.SetSubject(subject)
	h.SetDate(time.Now())
	h.Set("Auto-Submitted", "auto-replied (vacation)")
	if err := h.GenerateMessageIDWithHostname(s.cfg.Sieve.Hostname); err != nil {
		return nil, err
	}
	if id, err := orig.MessageID(); err == nil && id != "" {
		h.SetMsgIDList("In-Reply-To", []string{id})
		refs, _ := orig.MsgIDList("References")
		h.SetMsgIDList("References", append(refs, id))
	}
	var buf bytes.Buffer
	if v.Mime {
		// :mime: the reason is a MIME entity, headers included.
		h.Set("MIME-Version", "1.0")
		if err := textproto.WriteHeader(&buf, h.Header.Header); err != nil {
			return nil, err
		}
		reason := strings.ReplaceAll(strings.ReplaceAll(v.Reason, "\r\n", "\n"), "\n", "\r\n")
		buf.WriteString(reason)
		return buf.Bytes(), nil
	}
	h.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	w, err := gomessage.CreateWriter(&buf, h.Header)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(v.Reason, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
