package webmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/emersion/go-vcard"
)

// Contact is one address book entry, stored as a vCard 4.0 object so it can
// be exported to (and imported from) any other address book as it is.
type Contact struct {
	ID       string
	Name     string
	Emails   []Labeled
	Phones   []Labeled
	Org      string
	Title    string
	Address  string
	Birthday string // YYYY-MM-DD, or --MM-DD without a year
	Website  string
	Notes    string
	Groups   []string
}

// Labeled is a value with its kind: work, home, mobile, other.
type Labeled struct {
	Label string
	Value string
}

// Email is the contact's first address, the one used to write to them.
func (c Contact) Email() string {
	if len(c.Emails) == 0 {
		return ""
	}
	return c.Emails[0].Value
}

// Display is the name, or the address for a contact saved without one.
func (c Contact) Display() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Email()
}

// collectedGroup holds addresses saved automatically when the user writes to
// someone new, so they autocomplete next time without cluttering the
// contacts the user added themselves.
const collectedGroup = "Emailed"

func (c Contact) collected() bool {
	return len(c.Groups) == 1 && c.Groups[0] == collectedGroup
}

func contactToCard(c Contact) vcard.Card {
	card := vcard.Card{}
	card.SetValue(vcard.FieldVersion, "4.0")
	card.SetValue(vcard.FieldUID, c.ID)
	card.SetValue(vcard.FieldFormattedName, c.Display())
	given, family := splitName(c.Name)
	card.SetName(&vcard.Name{GivenName: given, FamilyName: family})
	for _, e := range c.Emails {
		f := &vcard.Field{Value: e.Value, Params: vcard.Params{}}
		if e.Label != "" {
			f.Params.Set(vcard.ParamType, e.Label)
		}
		card.Add(vcard.FieldEmail, f)
	}
	for _, p := range c.Phones {
		f := &vcard.Field{Value: p.Value, Params: vcard.Params{}}
		if p.Label != "" {
			label := p.Label
			if label == "mobile" {
				label = vcard.TypeCell
			}
			f.Params.Set(vcard.ParamType, label)
		}
		card.Add(vcard.FieldTelephone, f)
	}
	if c.Org != "" {
		card.SetValue(vcard.FieldOrganization, c.Org)
	}
	if c.Title != "" {
		card.SetValue(vcard.FieldTitle, c.Title)
	}
	if c.Address != "" {
		// The address is kept as typed, in the street component, rather
		// than guessed into fields; every address book shows it intact.
		card.SetAddress(&vcard.Address{StreetAddress: c.Address, Field: &vcard.Field{Params: vcard.Params{}}})
	}
	if c.Birthday != "" {
		// vCard writes 1985-02-14 as 19850214 and a birthday without a
		// year as --0214; the leading dashes are what mark the year as
		// missing, so they must survive.
		bday := strings.ReplaceAll(c.Birthday, "-", "")
		if strings.HasPrefix(c.Birthday, "--") {
			bday = "--" + bday
		}
		card.SetValue(vcard.FieldBirthday, bday)
	}
	if c.Website != "" {
		card.SetValue(vcard.FieldURL, c.Website)
	}
	if c.Notes != "" {
		card.SetValue(vcard.FieldNote, c.Notes)
	}
	// One CATEGORIES line per group: the library escapes the commas of a
	// joined list, which other address books would read as a single group.
	for _, g := range c.Groups {
		card.Add(vcard.FieldCategories, &vcard.Field{Value: g})
	}
	return card
}

func splitName(full string) (given, family string) {
	parts := strings.Fields(full)
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	}
	return strings.Join(parts[:len(parts)-1], " "), parts[len(parts)-1]
}

func cardToContact(card vcard.Card) Contact {
	c := Contact{ID: card.Value(vcard.FieldUID), Name: card.PreferredValue(vcard.FieldFormattedName)}
	if c.Name == "" {
		if n := card.Name(); n != nil {
			c.Name = strings.TrimSpace(n.GivenName + " " + n.FamilyName)
		}
	}
	label := func(f *vcard.Field) string {
		for _, t := range f.Params.Types() {
			switch t = strings.ToLower(t); t {
			case "work", "home":
				return t
			case "cell", "mobile":
				return "mobile"
			}
		}
		return ""
	}
	for _, f := range card[vcard.FieldEmail] {
		if v := strings.TrimSpace(f.Value); v != "" {
			c.Emails = append(c.Emails, Labeled{Label: label(f), Value: v})
		}
	}
	for _, f := range card[vcard.FieldTelephone] {
		if v := strings.TrimSpace(strings.TrimPrefix(f.Value, "tel:")); v != "" {
			c.Phones = append(c.Phones, Labeled{Label: label(f), Value: v})
		}
	}
	c.Org = strings.ReplaceAll(card.Value(vcard.FieldOrganization), ";", ", ")
	c.Org = strings.Trim(c.Org, ", ")
	c.Title = card.Value(vcard.FieldTitle)
	if a := card.Address(); a != nil {
		var lines []string
		for _, p := range []string{a.StreetAddress, a.ExtendedAddress, strings.TrimSpace(a.Locality + " " + a.Region + " " + a.PostalCode), a.Country} {
			if p = strings.TrimSpace(p); p != "" {
				lines = append(lines, p)
			}
		}
		c.Address = strings.Join(lines, "\n")
	}
	if b := card.Value(vcard.FieldBirthday); b != "" {
		c.Birthday = formatBirthday(b)
	}
	c.Website = card.Value(vcard.FieldURL)
	c.Notes = card.Value(vcard.FieldNote)
	for _, f := range card[vcard.FieldCategories] {
		for _, g := range strings.Split(f.Value, ",") {
			if g = strings.TrimSpace(g); g != "" && !contains(c.Groups, g) {
				c.Groups = append(c.Groups, g)
			}
		}
	}
	return c
}

// formatBirthday turns vCard's 19850214 or --0214 into 1985-02-14 or --02-14.
func formatBirthday(b string) string {
	b = strings.TrimSpace(b)
	if i := strings.IndexByte(b, 'T'); i > 0 {
		b = b[:i]
	}
	d := strings.ReplaceAll(b, "-", "")
	switch {
	case len(d) == 8:
		return d[:4] + "-" + d[4:6] + "-" + d[6:]
	case len(d) == 4 && strings.HasPrefix(b, "--"):
		return "--" + d[:2] + "-" + d[2:]
	}
	return b
}

func encodeCard(card vcard.Card) ([]byte, error) {
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(card); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// contacts returns the address book, sorted by name.
func (s *Server) contacts(ctx context.Context, sess *Session) ([]Contact, error) {
	var out []Contact
	err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollContacts)
		if err != nil {
			return err
		}
		for _, o := range objs {
			card, err := vcard.NewDecoder(bytes.NewReader(o.Data)).Decode()
			if err != nil {
				continue
			}
			c := cardToContact(card)
			c.ID = o.ID
			out = append(out, c)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Display()) < strings.ToLower(out[j].Display()) })
	return out, err
}

func (s *Server) putContact(ctx context.Context, sess *Session, c Contact) error {
	data, err := encodeCard(contactToCard(c))
	if err != nil {
		return err
	}
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		return st.PutObject(ctx, CollContacts, Object{ID: c.ID, Title: c.Display(), ContentType: "text/vcard", Data: data})
	})
}

func newObjectID() string {
	id, err := randomToken(18)
	if err != nil {
		panic(err) // crypto/rand failing leaves nothing safe to do
	}
	return id
}

// addressSuggestions are the addresses compose offers as the user types:
// every contact address, and each group as the list of its members.
func (s *Server) addressSuggestions(ctx context.Context, sess *Session) []Address {
	list, err := s.contacts(ctx, sess)
	if err != nil {
		return nil
	}
	var out []Address
	for _, c := range list {
		for _, e := range c.Emails {
			out = append(out, Address{Name: c.Name, Email: e.Value})
		}
	}
	return out
}

// rememberRecipients saves anyone the user wrote to who isn't in the
// address book yet, in the Emailed group.
func (s *Server) rememberRecipients(ctx context.Context, sess *Session, d *Draft) {
	list, err := s.contacts(ctx, sess)
	if err != nil {
		return
	}
	known := map[string]bool{strings.ToLower(sess.Address): true}
	for _, c := range list {
		for _, e := range c.Emails {
			known[strings.ToLower(e.Value)] = true
		}
	}
	for _, group := range [][]Address{d.To, d.Cc, d.Bcc} {
		for _, a := range group {
			key := strings.ToLower(a.Email)
			if a.Email == "" || known[key] {
				continue
			}
			known[key] = true
			c := Contact{ID: newObjectID(), Name: a.Name, Emails: []Labeled{{Value: a.Email}}, Groups: []string{collectedGroup}}
			if err := s.putContact(ctx, sess, c); err != nil {
				s.log.Warn("webmail: remember recipient", "user", sess.User, "error", err)
				return
			}
		}
	}
}

type contactsView struct {
	All      []Contact
	Shown    []Contact
	Groups   []string
	Group    string
	Query    string
	Selected *Contact
	Edit     *Contact
	// EmailRows and PhoneRows are the edit form's rows: the contact's
	// values plus blanks to add more.
	EmailRows []Labeled
	PhoneRows []Labeled
	Back      string
}

func matchesContact(c Contact, q string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	hay := strings.ToLower(c.Name + " " + c.Org + " " + c.Title + " " + c.Notes)
	for _, e := range c.Emails {
		hay += " " + strings.ToLower(e.Value)
	}
	for _, p := range c.Phones {
		hay += " " + p.Value
	}
	return strings.Contains(hay, q)
}

func (s *Server) contactsPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	all, err := s.contacts(r.Context(), sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	cv := &contactsView{All: all, Group: q.Get("g"), Query: strings.TrimSpace(q.Get("q"))}
	groups := map[string]bool{}
	for _, c := range all {
		for _, g := range c.Groups {
			groups[g] = true
		}
		inGroup := cv.Group == ""
		for _, g := range c.Groups {
			if g == cv.Group {
				inGroup = true
			}
		}
		// The auto-collected addresses only show when asked for.
		if cv.Group == "" && c.collected() && cv.Query == "" {
			inGroup = false
		}
		if inGroup && matchesContact(c, cv.Query) {
			cv.Shown = append(cv.Shown, c)
		}
	}
	for g := range groups {
		cv.Groups = append(cv.Groups, g)
	}
	sort.Strings(cv.Groups)
	id := q.Get("id")
	for i := range all {
		if all[i].ID == id {
			cv.Selected = &all[i]
		}
	}
	if q.Get("edit") == "1" || q.Get("new") == "1" {
		edit := Contact{}
		if cv.Selected != nil && q.Get("new") != "1" {
			edit = *cv.Selected
		} else {
			edit.Name = q.Get("name")
			if e := q.Get("email"); e != "" {
				edit.Emails = []Labeled{{Value: e}}
			}
			if cv.Group != "" {
				edit.Groups = []string{cv.Group}
			}
		}
		cv.Edit = &edit
		cv.EmailRows = append(append([]Labeled{}, edit.Emails...), Labeled{}, Labeled{})
		cv.PhoneRows = append(append([]Labeled{}, edit.Phones...), Labeled{}, Labeled{})
	}
	cv.Back = q.Get("back")
	v := view{Title: "Contacts", Session: sess, App: "contacts", Notice: notices[q.Get("n")], Contacts: cv}
	s.render(w, "contacts.html", http.StatusOK, v)
}

func contactsURL(id, group string, extra ...string) string {
	v := url.Values{}
	if id != "" {
		v.Set("id", id)
	}
	if group != "" {
		v.Set("g", group)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	if len(v) == 0 {
		return "/contacts"
	}
	return "/contacts?" + v.Encode()
}

func (s *Server) contactsSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	op := r.PostFormValue("op")
	group := r.PostFormValue("g")
	switch op {
	case "delete":
		id := r.PostFormValue("id")
		err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			return st.DeleteObject(r.Context(), CollContacts, id)
		})
		if err != nil {
			s.fail(w, r, sess, err)
			return
		}
		http.Redirect(w, r, contactsURL("", group, "n", "contact-deleted"), http.StatusSeeOther)
		return
	case "save":
	case "add-sender":
		s.addSender(w, r, sess)
		return
	default:
		s.fail(w, r, sess, ErrNotFound)
		return
	}

	c := Contact{
		ID:   r.PostFormValue("id"),
		Name: strings.TrimSpace(r.PostFormValue("name")), Org: strings.TrimSpace(r.PostFormValue("org")),
		Title: strings.TrimSpace(r.PostFormValue("title")), Address: strings.TrimSpace(normaliseText(r.PostFormValue("address"))),
		Birthday: strings.TrimSpace(r.PostFormValue("birthday")), Website: strings.TrimSpace(r.PostFormValue("website")),
		Notes: strings.TrimSpace(normaliseText(r.PostFormValue("notes"))),
	}
	labels := r.PostForm["email_label"]
	for i, e := range r.PostForm["email"] {
		if e = strings.TrimSpace(e); e != "" {
			l := ""
			if i < len(labels) {
				l = labels[i]
			}
			c.Emails = append(c.Emails, Labeled{Label: l, Value: e})
		}
	}
	labels = r.PostForm["phone_label"]
	for i, p := range r.PostForm["phone"] {
		if p = strings.TrimSpace(p); p != "" {
			l := ""
			if i < len(labels) {
				l = labels[i]
			}
			c.Phones = append(c.Phones, Labeled{Label: l, Value: p})
		}
	}
	for _, g := range strings.Split(r.PostFormValue("groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			c.Groups = append(c.Groups, g)
		}
	}
	if c.Name == "" && len(c.Emails) == 0 {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Give the contact a name or an email address.")
		return
	}
	for _, e := range c.Emails {
		if _, err := parseList(e.Value); err != nil || strings.ContainsAny(e.Value, ",;") {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "“"+e.Value+"” isn't a valid email address.")
			return
		}
	}
	if c.ID == "" {
		c.ID = newObjectID()
	}
	if err := s.putContact(r.Context(), sess, c); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if back := localBack(r.PostFormValue("back"), ""); back != "" {
		redirectLocal(w, r, setParam(back, "n", "contact-saved"))
		return
	}
	http.Redirect(w, r, contactsURL(c.ID, group, "n", "contact-saved"), http.StatusSeeOther)
}

func normaliseText(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// addSender saves a message's sender from the reading pane in one click.
func (s *Server) addSender(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := localBack(r.PostFormValue("back"), "/mail")
	email := strings.TrimSpace(r.PostFormValue("email"))
	if email == "" {
		redirectLocal(w, r, back)
		return
	}
	all, err := s.contacts(r.Context(), sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	c := Contact{ID: newObjectID(), Name: strings.TrimSpace(r.PostFormValue("name")), Emails: []Labeled{{Value: email}}}
	for _, existing := range all {
		for _, e := range existing.Emails {
			if strings.EqualFold(e.Value, email) {
				if !existing.collected() {
					redirectLocal(w, r, setParam(back, "n", "contact-exists"))
					return
				}
				// Promote an auto-collected address to a real contact.
				c.ID = existing.ID
				if c.Name == "" {
					c.Name = existing.Name
				}
			}
		}
	}
	if err := s.putContact(r.Context(), sess, c); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	redirectLocal(w, r, setParam(back, "n", "contact-saved"))
}

// contactsExport downloads the address book (or one group) as a .vcf file.
func (s *Server) contactsExport(w http.ResponseWriter, r *http.Request, sess *Session) {
	all, err := s.contacts(r.Context(), sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	group := r.URL.Query().Get("g")
	var buf bytes.Buffer
	enc := vcard.NewEncoder(&buf)
	for _, c := range all {
		if group != "" && !contains(c.Groups, group) {
			continue
		}
		if err := enc.Encode(contactToCard(c)); err != nil {
			s.fail(w, r, sess, err)
			return
		}
	}
	name := "contacts.vcf"
	if group != "" {
		name = group + ".vcf"
	}
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Cache-Control", "private, no-store")
	// #nosec G705 -- a vCard download served as an attachment with nosniff
	_, _ = w.Write(buf.Bytes())
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// maxImportCards bounds one import, so a huge file can't tie up the
// session's IMAP connection for minutes.
const maxImportCards = 2000

// contactsImport adds the cards from an uploaded .vcf file. A card whose
// UID is already in the address book replaces that contact, so importing
// the same file twice doesn't duplicate everyone.
func (s *Server) contactsImport(w http.ResponseWriter, r *http.Request, sess *Session) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) == 0 {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Choose a .vcf file to import.")
		return
	}
	f, err := r.MultipartForm.File["file"][0].Open()
	if err != nil {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "The file couldn't be read.")
		return
	}
	defer func() { _ = f.Close() }()
	dec := vcard.NewDecoder(io.LimitReader(f, 20<<20))
	n := 0
	for n < maxImportCards {
		card, err := dec.Decode()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "That file isn't a vCard (.vcf) file, or it is damaged.")
			return
		}
		c := cardToContact(card)
		if c.ID == "" {
			c.ID = newObjectID()
		}
		if c.Name == "" && len(c.Emails) == 0 {
			continue
		}
		if err := s.putContact(r.Context(), sess, c); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		n++
	}
	http.Redirect(w, r, "/contacts?n=contacts-imported", http.StatusSeeOther)
}

// addressesAPI feeds compose's address autocomplete.
func (s *Server) addressesAPI(w http.ResponseWriter, r *http.Request, sess *Session) {
	all, err := s.contacts(r.Context(), sess)
	if err != nil {
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	type suggestion struct {
		Label string `json:"label"`
		Value string `json:"value"`
		Group bool   `json:"group,omitempty"`
	}
	out := []suggestion{}
	members := map[string][]string{}
	for _, c := range all {
		for _, e := range c.Emails {
			a := Address{Name: c.Name, Email: e.Value}
			out = append(out, suggestion{Label: c.Display() + " <" + e.Value + ">", Value: formatAddress(a)})
		}
		if c.Email() == "" {
			continue
		}
		for _, g := range c.Groups {
			if g != collectedGroup {
				members[g] = append(members[g], formatAddress(Address{Name: c.Name, Email: c.Email()}))
			}
		}
	}
	for g, m := range members {
		out = append(out, suggestion{Label: g + " (group, " + plural2(len(m), "person", "people") + ")", Value: strings.Join(m, ", "), Group: true})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(out)
}

func plural2(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// senderIsContact is a message decorator: it tells the reading pane whether
// to offer "Add to contacts".
func senderIsContact(s *Server, ctx context.Context, sess *Session, v *view) {
	if v.Message == nil || len(v.Message.From) == 0 {
		return
	}
	all, err := s.contacts(ctx, sess)
	if err != nil {
		return
	}
	from := strings.ToLower(v.Message.From[0].Email)
	for _, c := range all {
		for _, e := range c.Emails {
			if strings.ToLower(e.Value) == from && !c.collected() {
				v.Message.SenderContact = c.ID
				return
			}
		}
	}
}

func init() {
	messageDecorators = append(messageDecorators, senderIsContact)
}
