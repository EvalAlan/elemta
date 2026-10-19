package webmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Mail filters and the out-of-office reply are one Sieve script on the
// user's ManageSieve server, so they run at delivery whether or not the
// webmail is open, and other Sieve-aware clients see them. The structured
// rules travel in the script itself, in a header comment, so the form can
// be rebuilt from what the server holds; the Sieve below the comment is
// generated from them and is what actually runs.

// sieveScriptName is the script the webmail owns.
const sieveScriptName = "elemta"

// filtersMarker starts the comment line that carries the rules.
const filtersMarker = "# elemta-filters v1 "

// FilterSet is everything on the Filters page.
type FilterSet struct {
	Rules    []FilterRule `json:"rules"`
	Vacation Vacation     `json:"vacation"`
}

// FilterRule is one "if this, do that".
type FilterRule struct {
	Name       string            `json:"name"`
	Enabled    bool              `json:"enabled"`
	MatchAll   bool              `json:"all"` // all conditions, rather than any
	Conditions []FilterCondition `json:"if"`
	Actions    []FilterAction    `json:"then"`
}

// FilterCondition tests one part of a message.
type FilterCondition struct {
	Field string `json:"field"` // from, to, cc, tocc, subject, body, size, or header:<Name>
	Op    string `json:"op"`    // contains, not-contains, is, not-is, matches, regex, over, under
	Value string `json:"value"`
}

// FilterAction is one thing done to a matching message.
type FilterAction struct {
	Type string `json:"type"` // fileinto, copyto, read, flag, tag, redirect, discard, reject, stop
	Arg  string `json:"arg,omitempty"`
}

// Vacation is the out-of-office reply.
type Vacation struct {
	Enabled bool   `json:"enabled"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Days    int    `json:"days"`
	Start   string `json:"start,omitempty"` // YYYY-MM-DD, inclusive
	End     string `json:"end,omitempty"`
	// Aliases are the user's other addresses; mail sent to them is
	// answered too.
	Aliases string `json:"aliases,omitempty"`
}

var (
	headerNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,76}$`)
	sizeRE       = regexp.MustCompile(`^\d{1,9}[KMG]?$`)
)

// Describe is a rule in words, for the list on the Filters page.
func (r FilterRule) Describe() string {
	var conds []string
	for _, c := range r.Conditions {
		conds = append(conds, c.describe())
	}
	join := " or "
	if r.MatchAll {
		join = " and "
	}
	var acts []string
	for _, a := range r.Actions {
		acts = append(acts, a.describe())
	}
	if len(conds) == 0 {
		return "Every message: " + strings.Join(acts, ", ")
	}
	return "If " + strings.Join(conds, join) + ": " + strings.Join(acts, ", ")
}

var fieldLabels = map[string]string{"from": "From", "to": "To", "cc": "Cc", "tocc": "To or Cc", "subject": "Subject", "body": "Body", "size": "Size"}
var opLabels = map[string]string{"contains": "contains", "not-contains": "doesn't contain", "is": "is", "not-is": "isn't", "matches": "matches", "regex": "matches the pattern", "over": "is over", "under": "is under"}

func (c FilterCondition) describe() string {
	field := fieldLabels[c.Field]
	if strings.HasPrefix(c.Field, "header:") {
		field = strings.TrimPrefix(c.Field, "header:")
	}
	return fmt.Sprintf("%s %s “%s”", field, opLabels[c.Op], c.Value)
}

func (a FilterAction) describe() string {
	switch a.Type {
	case "fileinto":
		return "move to " + a.Arg
	case "copyto":
		return "copy to " + a.Arg
	case "read":
		return "mark read"
	case "flag":
		return "flag"
	case "tag":
		return "tag " + a.Arg
	case "redirect":
		return "forward to " + a.Arg
	case "discard":
		return "delete"
	case "reject":
		return "reject"
	case "stop":
		return "stop processing"
	}
	return a.Type
}

// validate checks a rule before it is turned into Sieve.
func (r FilterRule) validate() error {
	if len(r.Actions) == 0 {
		return errors.New("choose at least one action")
	}
	for _, c := range r.Conditions {
		switch {
		case c.Field == "size":
			if c.Op != "over" && c.Op != "under" {
				return errors.New("size can only be over or under a value")
			}
			if !sizeRE.MatchString(strings.ToUpper(c.Value)) {
				return errors.New("write sizes like 500K or 10M")
			}
		case strings.HasPrefix(c.Field, "header:"):
			if !headerNameRE.MatchString(strings.TrimPrefix(c.Field, "header:")) {
				return errors.New("a header name can only contain letters, digits and dashes")
			}
		case fieldLabels[c.Field] == "":
			return errors.New("unknown field " + c.Field)
		}
		if c.Field != "size" && (c.Op == "over" || c.Op == "under") {
			return errors.New("only size can be over or under")
		}
		if opLabels[c.Op] == "" {
			return errors.New("unknown comparison " + c.Op)
		}
		if c.Op == "regex" {
			if _, err := regexp.Compile(c.Value); err != nil {
				return errors.New("the pattern isn't a valid regular expression")
			}
		}
		if len(c.Value) > 500 || strings.ContainsAny(c.Value, "\r\n") {
			return errors.New("condition values must be one line, under 500 characters")
		}
	}
	for _, a := range r.Actions {
		switch a.Type {
		case "fileinto", "copyto":
			if a.Arg == "" {
				return errors.New("choose a folder to move or copy to")
			}
		case "tag":
			if !tagRE.MatchString(a.Arg) || !isTagKeyword(a.Arg) {
				return errors.New("tags can use letters, numbers, dots, dashes and underscores")
			}
		case "redirect":
			if _, err := parseList(a.Arg); err != nil || strings.ContainsAny(a.Arg, ",;") || a.Arg == "" {
				return errors.New("forward to one valid email address")
			}
		case "read", "flag", "discard", "reject", "stop":
		default:
			return errors.New("unknown action " + a.Type)
		}
		if len(a.Arg) > 500 || strings.ContainsAny(a.Arg, "\r\n") {
			return errors.New("action values must be one line")
		}
	}
	return nil
}

// sieveString quotes s as a Sieve string. Multi-line text uses the
// text: form, with lines starting with a dot doubled as RFC 5228 requires.
func sieveString(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, ".") {
				lines[i] = "." + l
			}
		}
		return "text:\r\n" + strings.Join(lines, "\r\n") + "\r\n.\r\n"
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// generateSieve renders the filter set as a Sieve script, starting with
// the comment that lets the form read it back.
func generateSieve(fs FilterSet) (string, error) {
	blob, err := json.Marshal(fs)
	if err != nil {
		return "", err
	}
	need := map[string]bool{}
	var body strings.Builder

	if v := fs.Vacation; v.Enabled {
		need["vacation"] = true
		days := v.Days
		if days < 1 {
			days = 1
		}
		var conds []string
		if v.Start != "" {
			need["date"], need["relational"] = true, true
			conds = append(conds, `currentdate :value "ge" "date" `+sieveString(v.Start))
		}
		if v.End != "" {
			need["date"], need["relational"] = true, true
			conds = append(conds, `currentdate :value "le" "date" `+sieveString(v.End))
		}
		cmd := fmt.Sprintf("vacation :days %d", days)
		if v.Subject != "" {
			cmd += " :subject " + sieveString(v.Subject)
		}
		if aliases := splitAliases(v.Aliases); len(aliases) > 0 {
			var q []string
			for _, a := range aliases {
				q = append(q, sieveString(a))
			}
			cmd += " :addresses [" + strings.Join(q, ", ") + "]"
		}
		cmd += " " + sieveString(v.Body)
		// Never answer mailing lists, bulk mail or automated senders.
		guard := `not anyof (exists "list-id", header :contains "precedence" ["bulk", "list", "junk"], exists "auto-submitted")`
		if len(conds) > 0 {
			fmt.Fprintf(&body, "if allof (%s, %s) {\r\n  %s;\r\n}\r\n", strings.Join(conds, ", "), guard, cmd)
		} else {
			fmt.Fprintf(&body, "if %s {\r\n  %s;\r\n}\r\n", guard, cmd)
		}
	}

	for _, r := range fs.Rules {
		if !r.Enabled {
			continue
		}
		var tests []string
		for _, c := range r.Conditions {
			tests = append(tests, sieveTest(c, need))
		}
		// Flags must be set before the message is filed: fileinto stores
		// it with the flags as they are at that moment, so a tag added
		// after a move would never reach the moved copy. Stop goes last.
		ordered := append([]FilterAction{}, r.Actions...)
		sort.SliceStable(ordered, func(i, j int) bool { return actionRank(ordered[i].Type) < actionRank(ordered[j].Type) })
		var acts []string
		for _, a := range ordered {
			acts = append(acts, sieveAction(a, need))
		}
		if len(acts) == 0 {
			continue
		}
		fmt.Fprintf(&body, "# %s\r\n", strings.ReplaceAll(r.Name, "\n", " "))
		switch len(tests) {
		case 0:
			fmt.Fprintf(&body, "if true {\r\n")
		case 1:
			fmt.Fprintf(&body, "if %s {\r\n", tests[0])
		default:
			of := "anyof"
			if r.MatchAll {
				of = "allof"
			}
			fmt.Fprintf(&body, "if %s (%s) {\r\n", of, strings.Join(tests, ", "))
		}
		for _, a := range acts {
			fmt.Fprintf(&body, "  %s;\r\n", a)
		}
		body.WriteString("}\r\n")
	}

	var out strings.Builder
	// The rules ride along base64-encoded, so no character in them can end
	// the comment early or be read as Sieve.
	out.WriteString(filtersMarker + base64.StdEncoding.EncodeToString(blob) + "\r\n")
	out.WriteString("# Generated by Elemta Webmail. Edit the filters there; changes made here are replaced on the next save.\r\n")
	if len(need) > 0 {
		var exts []string
		for e := range need {
			exts = append(exts, sieveString(e))
		}
		sort.Strings(exts)
		fmt.Fprintf(&out, "require [%s];\r\n", strings.Join(exts, ", "))
	}
	out.WriteString(body.String())
	return out.String(), nil
}

func splitAliases(s string) []string {
	var out []string
	for _, a := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
		if strings.Contains(a, "@") {
			out = append(out, a)
		}
	}
	return out
}

func actionRank(t string) int {
	switch t {
	case "read", "flag", "tag":
		return 0
	case "stop":
		return 2
	}
	return 1
}

func sieveTest(c FilterCondition, need map[string]bool) string {
	if c.Field == "size" {
		op := ":over"
		if c.Op == "under" {
			op = ":under"
		}
		return "size " + op + " " + strings.ToUpper(c.Value)
	}
	var match string
	negate := false
	switch c.Op {
	case "contains":
		match = ":contains"
	case "not-contains":
		match, negate = ":contains", true
	case "is":
		match = ":is"
	case "not-is":
		match, negate = ":is", true
	case "matches":
		match = ":matches"
	case "regex":
		match = ":regex"
		need["regex"] = true
	}
	var test string
	switch c.Field {
	case "body":
		need["body"] = true
		test = "body :text " + match + " " + sieveString(c.Value)
	case "from", "to", "cc", "tocc":
		hdrs := map[string]string{"from": `"from"`, "to": `"to"`, "cc": `"cc"`, "tocc": `["to", "cc"]`}[c.Field]
		// address tests compare the address itself, not the display name.
		// "contains" also matches names, which is what people mean when
		// they type one, so it tests the whole header.
		if c.Op == "contains" || c.Op == "not-contains" {
			test = "header " + match + " " + hdrs + " " + sieveString(c.Value)
		} else {
			test = "address " + match + " " + hdrs + " " + sieveString(c.Value)
		}
	case "subject":
		test = "header " + match + ` "subject" ` + sieveString(c.Value)
	default:
		test = "header " + match + " " + sieveString(strings.TrimPrefix(c.Field, "header:")) + " " + sieveString(c.Value)
	}
	if negate {
		return "not " + test
	}
	return test
}

func sieveAction(a FilterAction, need map[string]bool) string {
	switch a.Type {
	case "fileinto":
		need["fileinto"], need["mailbox"] = true, true
		return "fileinto :create " + sieveString(a.Arg)
	case "copyto":
		need["fileinto"], need["mailbox"], need["copy"] = true, true, true
		return "fileinto :copy :create " + sieveString(a.Arg)
	case "read":
		need["imap4flags"] = true
		return `addflag "\\Seen"`
	case "flag":
		need["imap4flags"] = true
		return `addflag "\\Flagged"`
	case "tag":
		need["imap4flags"] = true
		return "addflag " + sieveString(a.Arg)
	case "redirect":
		need["copy"] = true
		return "redirect :copy " + sieveString(a.Arg)
	case "discard":
		return "discard"
	case "reject":
		need["reject"] = true
		return `reject "This message was not accepted."`
	case "stop":
		return "stop"
	}
	return ""
}

// parseFilterScript recovers the rules from a script this webmail wrote.
// ok is false for a script written by something else.
func parseFilterScript(script string) (FilterSet, bool) {
	var fs FilterSet
	line, _, _ := strings.Cut(script, "\n")
	line = strings.TrimRight(line, "\r")
	if !strings.HasPrefix(line, filtersMarker) {
		return fs, false
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, filtersMarker))
	if err != nil || json.Unmarshal(blob, &fs) != nil {
		return fs, false
	}
	return fs, true
}

// ---- handlers --------------------------------------------------------------

type filtersView struct {
	Set      FilterSet
	Edit     *FilterRule
	EditIdx  int
	Folders  []Folder
	Foreign  string // name of an active script this webmail didn't write
	Raw      string
	ShowRaw  bool
	Problem  string
	Disabled bool // no ManageSieve server configured
	Conds    []FilterCondition
	Acts     []FilterAction
}

func (s *Server) withSieve(ctx context.Context, sess *Session, fn func(SieveConn) error) error {
	if s.sieve == nil {
		return errNoSieve
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := s.sieve(ctx, sess.User, pw)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return fn(c)
}

var errNoSieve = errors.New("webmail: no ManageSieve server configured")

// loadFilters reads the webmail's script and notes any other active one.
func (s *Server) loadFilters(ctx context.Context, sess *Session) (FilterSet, string, string, error) {
	var fs FilterSet
	var foreign, raw string
	err := s.withSieve(ctx, sess, func(c SieveConn) error {
		scripts, err := c.List()
		if err != nil {
			return err
		}
		ours := false
		for _, sc := range scripts {
			if sc.Name == sieveScriptName {
				ours = true
			} else if sc.Active {
				foreign = sc.Name
			}
		}
		if !ours {
			return nil
		}
		raw, err = c.Get(sieveScriptName)
		if err != nil {
			return err
		}
		fs, _ = parseFilterScript(raw)
		return nil
	})
	return fs, foreign, raw, err
}

func (s *Server) saveFilters(ctx context.Context, sess *Session, fs FilterSet) error {
	script, err := generateSieve(fs)
	if err != nil {
		return err
	}
	return s.withSieve(ctx, sess, func(c SieveConn) error {
		if err := c.Put(sieveScriptName, script); err != nil {
			return err
		}
		return c.SetActive(sieveScriptName)
	})
}

func (s *Server) filtersPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	fv := &filtersView{EditIdx: -1}
	v := view{Title: "Filters", Session: sess, App: "settings", SettingsTab: "filters", Filters: fv, Notice: notices[q.Get("n")]}
	s.withFolders(r, sess, &v)
	fv.Folders = v.Folders
	if s.sieve == nil {
		fv.Disabled = true
		s.render(w, "filters.html", http.StatusOK, v)
		return
	}
	set, foreign, raw, err := s.loadFilters(r.Context(), sess)
	if err != nil {
		s.log.Warn("webmail: read filters", "user", sess.User, "error", err)
		v.Problem = "The filter server didn't respond, so your filters can't be shown right now."
		s.render(w, "filters.html", http.StatusBadGateway, v)
		return
	}
	fv.Set, fv.Foreign, fv.Raw, fv.ShowRaw = set, foreign, raw, q.Get("raw") == "1"
	if fv.Set.Vacation.Days == 0 {
		fv.Set.Vacation.Days = 1
	}
	switch {
	case q.Get("new") == "1":
		rule := FilterRule{Enabled: true, MatchAll: true}
		if from := q.Get("from"); from != "" {
			rule.Name = "Mail from " + from
			rule.Conditions = []FilterCondition{{Field: "from", Op: "is", Value: from}}
		}
		fv.Edit = &rule
	case q.Get("edit") != "":
		i, err := strconv.Atoi(q.Get("edit"))
		if err == nil && i >= 0 && i < len(set.Rules) {
			fv.Edit, fv.EditIdx = &set.Rules[i], i
		}
	}
	if fv.Edit != nil {
		fv.Conds = append(append([]FilterCondition{}, fv.Edit.Conditions...), make([]FilterCondition, max(0, 4-len(fv.Edit.Conditions)))...)
		fv.Acts = append(append([]FilterAction{}, fv.Edit.Actions...), make([]FilterAction, max(0, 3-len(fv.Edit.Actions)))...)
	}
	s.render(w, "filters.html", http.StatusOK, v)
}

func (s *Server) filtersSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx := r.Context()
	set, _, _, err := s.loadFilters(ctx, sess)
	if err != nil {
		s.fail(w, r, sess, fmt.Errorf("webmail: read filters: %w", err))
		return
	}
	notice := "filters-saved"
	idx, idxErr := strconv.Atoi(r.PostFormValue("idx"))
	inRange := idxErr == nil && idx >= 0 && idx < len(set.Rules)
	switch op := r.PostFormValue("op"); op {
	case "vacation":
		v := Vacation{
			Enabled: r.PostFormValue("enabled") == "1", Subject: strings.TrimSpace(r.PostFormValue("subject")),
			Body: strings.TrimSpace(normaliseText(r.PostFormValue("body"))), Start: r.PostFormValue("start"), End: r.PostFormValue("end"),
			Aliases: strings.TrimSpace(r.PostFormValue("aliases")),
		}
		v.Days, _ = strconv.Atoi(r.PostFormValue("days"))
		if v.Days < 1 || v.Days > 30 {
			v.Days = 1
		}
		for _, d := range []string{v.Start, v.End} {
			if d != "" {
				if _, err := time.Parse("2006-01-02", d); err != nil {
					s.renderProblem(w, r, sess, http.StatusBadRequest, "Use dates like 2026-12-24.")
					return
				}
			}
		}
		if v.Enabled && v.Body == "" {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "Write the reply people will get.")
			return
		}
		if len(v.Body) > 10000 || len(v.Subject) > 300 || strings.ContainsAny(v.Subject, "\r\n") {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "The reply is too long.")
			return
		}
		set.Vacation = v
		notice = "vacation-saved"
	case "save":
		rule := FilterRule{Name: strings.TrimSpace(r.PostFormValue("name")), Enabled: r.PostFormValue("enabled") == "1", MatchAll: r.PostFormValue("match") != "any"}
		fields, ops, vals := r.PostForm["cond_field"], r.PostForm["cond_op"], r.PostForm["cond_value"]
		hdrs := r.PostForm["cond_header"]
		for i := range fields {
			if i >= len(ops) || i >= len(vals) || strings.TrimSpace(vals[i]) == "" || fields[i] == "" {
				continue
			}
			f := fields[i]
			if f == "header" {
				h := ""
				if i < len(hdrs) {
					h = strings.TrimSpace(hdrs[i])
				}
				f = "header:" + h
			}
			rule.Conditions = append(rule.Conditions, FilterCondition{Field: f, Op: ops[i], Value: strings.TrimSpace(vals[i])})
		}
		types, args := r.PostForm["act_type"], r.PostForm["act_arg"]
		for i, t := range types {
			if t == "" {
				continue
			}
			a := FilterAction{Type: t}
			if i < len(args) {
				a.Arg = strings.TrimSpace(args[i])
			}
			if t == "fileinto" || t == "copyto" {
				if f := r.PostForm["act_folder"]; i < len(f) && f[i] != "" {
					a.Arg = f[i]
				}
			}
			rule.Actions = append(rule.Actions, a)
		}
		if rule.Name == "" {
			rule.Name = "Filter"
		}
		if err := rule.validate(); err != nil {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "This filter can't be saved: "+err.Error()+".")
			return
		}
		if inRange {
			set.Rules[idx] = rule
		} else {
			set.Rules = append(set.Rules, rule)
		}
	case "delete":
		if inRange {
			set.Rules = append(set.Rules[:idx], set.Rules[idx+1:]...)
		}
	case "up", "down":
		j := idx - 1
		if op == "down" {
			j = idx + 1
		}
		if inRange && j >= 0 && j < len(set.Rules) {
			set.Rules[idx], set.Rules[j] = set.Rules[j], set.Rules[idx]
		}
	case "toggle":
		if inRange {
			set.Rules[idx].Enabled = !set.Rules[idx].Enabled
		}
	default:
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	if err := s.saveFilters(ctx, sess, set); err != nil {
		if errors.Is(err, ErrSieveRejected) {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "The mail server rejected these filters: "+strings.TrimPrefix(err.Error(), ErrSieveRejected.Error()+": "))
			return
		}
		s.fail(w, r, sess, fmt.Errorf("webmail: save filters: %w", err))
		return
	}
	http.Redirect(w, r, "/filters?"+url.Values{"n": {notice}}.Encode(), http.StatusSeeOther)
}
