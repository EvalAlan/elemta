package webmail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

type composeView struct {
	To, Cc, Bcc string
	Subject     string
	Text        string
	InReplyTo   string
	References  string
	Mode        string
	ShowCc      bool
	// OrigFolder and OrigUID name the message replied to or forwarded, so
	// it can be marked answered or forwarded once this one is sent.
	OrigFolder string
	OrigUID    uint32
	// DraftUID is the saved draft being edited, replaced on save and
	// removed on send.
	DraftUID uint32
	// Forwarded lists the original's attachments, carried over on forward.
	Forwarded    []Part
	HighPriority bool
	Receipt      bool
	// From is the address and name the message goes out as.
	From Address
	// Suggestions are addresses offered as the user types a recipient.
	Suggestions []Address
}

func (s *Server) composePage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	prefs := s.prefs(r.Context(), sess)
	cv := &composeView{Mode: q.Get("mode"), To: q.Get("to"), Subject: q.Get("subject"), From: prefs.fromAddress(sess.Address)}
	v := view{Title: "New message", Session: sess, Folder: q.Get("f"), Compose: cv}
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		folders, err := st.Folders(r.Context())
		if err != nil {
			return err
		}
		v.Folders = folders
		uid, ok := parseUID(q.Get("uid"))
		if cv.Mode == "" || !ok {
			cv.Mode = ""
			cv.Text = signatureBlock(prefs, false)
			return nil
		}
		raw, err := st.Raw(r.Context(), q.Get("f"), uid, s.maxMessage())
		if err != nil {
			return err
		}
		orig, err := parseMessage(raw)
		if err != nil {
			return err
		}
		if cv.Mode == "draft" {
			prefillDraft(cv, orig)
			cv.DraftUID = uid
			return nil
		}
		cv.OrigFolder, cv.OrigUID = q.Get("f"), uid
		prefillReply(cv, orig, sess.Address, prefs)
		if cv.Mode == "forward" {
			cv.Forwarded = orig.Attachments()
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	cv.Suggestions = s.addressSuggestions(r.Context(), sess)
	s.render(w, "compose.html", http.StatusOK, v)
}

// signatureBlock is the signature as it goes into a new message, with the
// conventional "-- " separator that lets clients recognise and trim it.
func signatureBlock(p Settings, reply bool) string {
	if strings.TrimSpace(p.Signature) == "" {
		return ""
	}
	sig := strings.ReplaceAll(p.Signature, "\r\n", "\n")
	if reply {
		return "\n\n-- \n" + sig
	}
	return "\n\n-- \n" + sig + "\n"
}

// prefillDraft reopens a saved draft for editing.
func prefillDraft(cv *composeView, orig *Message) {
	cv.Mode = "draft"
	cv.To, cv.Cc = formatList(orig.To), formatList(orig.Cc)
	cv.ShowCc = cv.Cc != ""
	cv.Subject = orig.Subject
	cv.Text = orig.Text
	if cv.Text == "" && orig.HTML != "" {
		cv.Text = htmlToText(orig.HTML)
	}
	cv.InReplyTo = orig.InReplyTo
	cv.References = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(orig.References), orig.InReplyTo))
	cv.HighPriority = orig.HighPriority
	cv.Receipt = orig.ReceiptTo != ""
}

// prefillReply fills a reply, reply-all or forward from the original.
func prefillReply(cv *composeView, orig *Message, self string, prefs Settings) {
	quoted := quoteText(orig)
	sig := signatureBlock(prefs, true)
	when := orig.Date.Format("Mon, Jan 2, 2006 at 15:04")
	switch cv.Mode {
	case "forward":
		cv.Subject = prefixSubject("Fwd: ", orig.Subject)
		cv.Text = sig + "\n\n---------- Forwarded message ----------\nFrom: " + formatList(orig.From) +
			"\nDate: " + when + "\nSubject: " + orig.Subject +
			"\nTo: " + formatList(orig.To) + "\n\n" + bodyText(orig)
	case "reply", "replyall":
		cv.Subject = prefixSubject("Re: ", orig.Subject)
		to := orig.ReplyTo
		if len(to) == 0 {
			to = orig.From
		}
		cv.To = formatList(to)
		if cv.Mode == "replyall" {
			var cc []Address
			skip := map[string]bool{strings.ToLower(self): true}
			for _, a := range to {
				skip[strings.ToLower(a.Email)] = true
			}
			for _, a := range append(append([]Address{}, orig.To...), orig.Cc...) {
				if !skip[strings.ToLower(a.Email)] {
					skip[strings.ToLower(a.Email)] = true
					cc = append(cc, a)
				}
			}
			cv.Cc = formatList(cc)
			cv.ShowCc = len(cc) > 0
		}
		cv.InReplyTo = orig.MessageID
		cv.References = orig.References
		attribution := "On " + when + ", " + formatList(orig.From) + " wrote:\n" + quoted
		if prefs.SignatureAbove {
			cv.Text = sig + "\n\n" + attribution
		} else {
			cv.Text = "\n\n" + attribution + sig
		}
	default:
		cv.Mode = ""
	}
}

func prefixSubject(prefix, subject string) string {
	if strings.HasPrefix(strings.ToLower(subject), strings.ToLower(prefix)) {
		return subject
	}
	return prefix + subject
}

func bodyText(m *Message) string {
	if m.Text == "" && m.HTML != "" {
		return htmlToText(m.HTML)
	}
	return m.Text
}

func quoteText(m *Message) string {
	lines := strings.Split(strings.ReplaceAll(bodyText(m), "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = "> " + l
	}
	return strings.Join(lines, "\n")
}

// plainNameRE matches display names that need no quoting in an address field.
var plainNameRE = regexp.MustCompile(`^[\p{L}\p{N} .'-]+$`)

func formatList(list []Address) string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a.Email == "" {
			continue
		}
		out = append(out, formatAddress(a))
	}
	return strings.Join(out, ", ")
}

func formatAddress(a Address) string {
	switch {
	case a.Name == "":
		return a.Email
	case plainNameRE.MatchString(a.Name):
		return a.Name + " <" + a.Email + ">"
	default:
		// Quotes, commas or non-ASCII in the name need RFC 5322 quoting
		// or encoding to survive being parsed back from the To field.
		return (&mail.Address{Name: a.Name, Address: a.Email}).String()
	}
}

func parseList(field string) ([]Address, error) {
	field = strings.TrimSpace(strings.Trim(strings.TrimSpace(field), ",;"))
	if field == "" {
		return nil, nil
	}
	// People separate addresses with semicolons as often as commas.
	list, err := mail.ParseAddressList(strings.ReplaceAll(field, ";", ","))
	if err != nil {
		return nil, err
	}
	out := make([]Address, 0, len(list))
	for _, a := range list {
		out = append(out, Address{Name: a.Name, Email: a.Address})
	}
	return out, nil
}

func (s *Server) composeSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	prefs := s.prefs(r.Context(), sess)
	cv := &composeView{
		To: r.PostFormValue("to"), Cc: r.PostFormValue("cc"), Bcc: r.PostFormValue("bcc"),
		Subject: r.PostFormValue("subject"), Text: r.PostFormValue("body"),
		InReplyTo: r.PostFormValue("in_reply_to"), References: r.PostFormValue("references"),
		Mode: r.PostFormValue("mode"), OrigFolder: r.PostFormValue("orig_f"),
		HighPriority: r.PostFormValue("priority") == "high", Receipt: r.PostFormValue("receipt") == "1",
		From: prefs.fromAddress(sess.Address),
	}
	cv.OrigUID, _ = parseUID(r.PostFormValue("orig_uid"))
	cv.DraftUID, _ = parseUID(r.PostFormValue("draft_uid"))
	cv.ShowCc = cv.Cc != "" || cv.Bcc != ""
	saveDraft := r.PostFormValue("op") == "save"
	v := view{Title: "New message", Session: sess, Compose: cv}

	again := func(status int, problem string) {
		_ = s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			v.Folders, _ = st.Folders(r.Context())
			return nil
		})
		cv.Suggestions = s.addressSuggestions(r.Context(), sess)
		v.Problem = problem
		s.render(w, "compose.html", status, v)
	}

	d := &Draft{
		From: cv.From, Subject: cv.Subject, Text: cv.Text, InReplyTo: cv.InReplyTo, References: cv.References,
		HighPriority: cv.HighPriority,
	}
	if cv.Receipt {
		d.ReceiptTo = sess.Address
	}
	if prefs.ReplyTo != "" {
		if a, err := mail.ParseAddress(prefs.ReplyTo); err == nil {
			d.ReplyTo = []Address{{Name: a.Name, Email: a.Address}}
		}
	}
	var err error
	for _, f := range []struct {
		label string
		value string
		dst   *[]Address
	}{{"To", cv.To, &d.To}, {"Cc", cv.Cc, &d.Cc}, {"Bcc", cv.Bcc, &d.Bcc}} {
		if *f.dst, err = parseList(f.value); err != nil {
			again(http.StatusBadRequest, "Check the addresses in "+f.label+". Separate them with commas.")
			return
		}
	}
	if !saveDraft && len(d.Recipients()) == 0 {
		again(http.StatusBadRequest, "Add at least one recipient.")
		return
	}
	total := 0
	if r.MultipartForm != nil {
		for _, fh := range r.MultipartForm.File["attachments"] {
			f, err := fh.Open()
			if err != nil {
				again(http.StatusBadRequest, "An attachment couldn't be read. Attach it again.")
				return
			}
			data, err := io.ReadAll(io.LimitReader(f, int64(s.cfg.MaxUploadMB)<<20+1))
			_ = f.Close()
			total += len(data)
			if err != nil || total > s.cfg.MaxUploadMB<<20 {
				again(http.StatusRequestEntityTooLarge, fmt.Sprintf("Attachments are limited to %d MB in total.", s.cfg.MaxUploadMB))
				return
			}
			d.Attachments = append(d.Attachments, Attachment{Filename: fh.Filename, ContentType: fh.Header.Get("Content-Type"), Data: data})
		}
	}
	// Forwarding carries the original's attachments that are still ticked.
	if cv.Mode == "forward" && cv.OrigFolder != "" && cv.OrigUID != 0 && len(r.PostForm["fwd_part"]) > 0 {
		var raw []byte
		err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			var err error
			raw, err = st.Raw(r.Context(), cv.OrigFolder, cv.OrigUID, s.maxMessage())
			return err
		})
		if err != nil {
			again(http.StatusBadGateway, "The original message's attachments couldn't be read. Try again.")
			return
		}
		for _, n := range r.PostForm["fwd_part"] {
			idx := 0
			if _, err := fmt.Sscan(n, &idx); err != nil || idx <= 0 {
				continue
			}
			part, body, err := findPart(raw, idx, "")
			if err != nil {
				continue
			}
			total += len(body)
			if total > s.cfg.MaxUploadMB<<20 {
				again(http.StatusRequestEntityTooLarge, fmt.Sprintf("Attachments are limited to %d MB in total.", s.cfg.MaxUploadMB))
				return
			}
			name := part.Filename
			if name == "" {
				name = fmt.Sprintf("part-%d", part.Index)
			}
			d.Attachments = append(d.Attachments, Attachment{Filename: name, ContentType: part.ContentType, Data: body})
		}
	}
	raw, err := d.Build(s.now())
	if err != nil {
		s.log.Error("webmail: build message", "error", err)
		again(http.StatusInternalServerError, "The message couldn't be prepared. Try again.")
		return
	}

	if saveDraft {
		err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			if err := st.Append(r.Context(), RoleDrafts, raw, true, true); err != nil {
				return err
			}
			return s.dropDraft(r.Context(), st, cv.DraftUID)
		})
		if err != nil {
			s.log.Warn("webmail: save draft", "user", sess.User, "error", err)
			again(http.StatusBadGateway, "The draft couldn't be saved. Try again.")
			return
		}
		http.Redirect(w, r, folderURL("INBOX", 1, "")+"&n=saved", http.StatusSeeOther)
		return
	}

	pw, err := s.sessions.password(sess)
	if err != nil {
		s.sessions.Destroy(sess.ID)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.submit.Submit(ctx, sess.User, pw, sess.Address, d.Recipients(), raw); err != nil {
		s.log.Warn("webmail: submit", "user", sess.User, "error", err)
		if errors.Is(err, ErrRejected) {
			again(http.StatusBadRequest, "The mail server refused this message: "+strings.TrimPrefix(err.Error(), ErrRejected.Error()+": "))
			return
		}
		again(http.StatusBadGateway, "The message couldn't be sent. It hasn't been lost: try Send again.")
		return
	}
	notice := "sent"
	if err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		if err := st.Append(r.Context(), RoleSent, raw, true, false); err != nil {
			return err
		}
		// Housekeeping after a successful send. Failures here don't undo
		// the send, so they're logged, not shown.
		if err := s.dropDraft(r.Context(), st, cv.DraftUID); err != nil {
			s.log.Warn("webmail: remove sent draft", "user", sess.User, "error", err)
		}
		if cv.OrigFolder != "" && cv.OrigUID != 0 {
			flag := FlagAnswered
			if cv.Mode == "forward" {
				flag = FlagForwarded
			}
			if err := st.SetFlags(r.Context(), cv.OrigFolder, []uint32{cv.OrigUID}, []string{flag}, true); err != nil {
				s.log.Warn("webmail: mark original", "user", sess.User, "error", err)
			}
		}
		return nil
	}); err != nil {
		s.log.Warn("webmail: save sent copy", "user", sess.User, "error", err)
		notice = "sent-nocopy"
	}
	s.rememberRecipients(r.Context(), sess, d)
	http.Redirect(w, r, folderURL("INBOX", 1, "")+"&n="+notice, http.StatusSeeOther)
}

// dropDraft removes the draft a message was edited from, now that a newer
// version has been saved or sent.
func (s *Server) dropDraft(ctx context.Context, st Mailstore, uid uint32) error {
	if uid == 0 {
		return nil
	}
	folders, err := st.Folders(ctx)
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f.Role == RoleDrafts {
			// Expunge outright: a superseded draft in Trash is clutter.
			return st.Expunge(ctx, f.Name, []uint32{uid})
		}
	}
	return nil
}
