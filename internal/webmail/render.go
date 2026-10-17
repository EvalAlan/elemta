package webmail

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"html/template"
	"io/fs"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// staticFiles is the static directory rooted so files serve at /static/<name>.
func staticFiles() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}

// assetVersions maps each static file to a short hash of its content.
// Asset URLs carry it (/static/app.js?v=…), so a deploy changes the URL and
// browsers never run new pages against a cached old script or stylesheet.
var assetVersions = func() map[string]string {
	out := map[string]string{}
	_ = fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[strings.TrimPrefix(path, "static/")] = hex.EncodeToString(sum[:6])
		return nil
	})
	return out
}()

func assetURL(name string) string {
	return "/static/" + name + "?v=" + assetVersions[name]
}

// partials are parsed into every page: icons and shared fragments.
var partials = []string{"templates/layout.html", "templates/icons.html", "templates/partials.html"}

// loadTemplates parses each page in templates/ together with the layout and
// partials. login.html stands alone because it has no app shell.
func loadTemplates() (map[string]*template.Template, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, path := range names {
		p := strings.TrimPrefix(path, "templates/")
		switch p {
		case "layout.html", "icons.html", "partials.html":
			continue
		case "login.html", "print.html", "source.html":
			t, err := template.New(p).Funcs(templateFuncs).ParseFS(templateFS, path, "templates/icons.html")
			if err != nil {
				return nil, fmt.Errorf("webmail: template %s: %w", p, err)
			}
			out[p] = t
			continue
		}
		t, err := template.New("layout.html").Funcs(templateFuncs).ParseFS(templateFS, append(append([]string{}, partials...), path)...)
		if err != nil {
			return nil, fmt.Errorf("webmail: template %s: %w", p, err)
		}
		out[p] = t
	}
	return out, nil
}

var templateFuncs = template.FuncMap{
	"asset":      assetURL,
	"shortDate":  shortDate,
	"longDate":   longDate,
	"clock":      clock,
	"humanSize":  humanSize,
	"addrs":      joinAddresses,
	"folderURL":  folderURL,
	"messageURL": messageURL,
	"partURL": func(folder string, uid uint32, n int) string {
		return "/mail/part?" + url.Values{"f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}, "n": {strconv.Itoa(n)}}.Encode()
	},
	"previewable": previewable,
	"inUIDs": func(u uint32, list []uint32) bool {
		for _, x := range list {
			if x == u {
				return true
			}
		}
		return false
	},
	// threadCard pairs a conversation message with the page, for the
	// thread-card template, which needs both.
	"threadCard": func(r Related, v view) map[string]any { return map[string]any{"R": r, "V": v} },
	"sourceURL": func(folder string, uid uint32) string {
		return "/mail/source?" + url.Values{"f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}}.Encode()
	},
	"printURL": func(folder string, uid uint32) string {
		return "/mail/print?" + url.Values{"f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}}.Encode()
	},
	"bodyURL": func(folder string, uid uint32, remote bool) string {
		v := url.Values{"f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}}
		if remote {
			v.Set("remote", "1")
		}
		return "/mail/body?" + v.Encode()
	},
	"rawURL": func(folder string, uid uint32) string {
		return "/mail/raw?" + url.Values{"f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}}.Encode()
	},
	"composeURL": func(mode, folder string, uid uint32) string {
		return "/compose?" + url.Values{"mode": {mode}, "f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}}.Encode()
	},
	"contactsURL": contactsURL,
	"hasPrefix":   strings.HasPrefix,
	"trimPrefix": func(s, prefix string) string {
		if !strings.HasPrefix(s, prefix) {
			return ""
		}
		return strings.TrimPrefix(s, prefix)
	},
	"fieldOptions": func() []option {
		return []option{{"from", "From"}, {"to", "To"}, {"cc", "Cc"}, {"tocc", "To or Cc"}, {"subject", "Subject"}, {"body", "Body"}, {"size", "Size"}, {"header", "Header…"}}
	},
	"opOptions": func() []option {
		return []option{{"contains", "contains"}, {"not-contains", "doesn't contain"}, {"is", "is"}, {"not-is", "isn't"}, {"matches", "matches (* and ?)"}, {"regex", "matches pattern"}, {"over", "is over"}, {"under", "is under"}}
	},
	"actionOptions": func() []option {
		return []option{{"fileinto", "Move to folder"}, {"copyto", "Copy to folder"}, {"read", "Mark as read"}, {"flag", "Flag"}, {"tag", "Tag"}, {"redirect", "Forward to"}, {"discard", "Delete"}, {"reject", "Reject"}, {"stop", "Stop processing more filters"}}
	},
	"tasksURL":   tasksURL,
	"calURL":     calURL,
	"calClass":   calClass,
	"evURL":      func(o Occurrence) string { return eventURL(o.Event.UID, o.Start) },
	"newEventAt": func(d time.Time, hour int) string { return newEventURL(d, hour) },
	"hourLabel": func(h24 bool, h int) string {
		return clock(h24, time.Date(2000, 1, 1, h, 0, 0, 0, time.UTC))
	},
	"whenOf": func(o Occurrence, loc *time.Location, h24 bool) string {
		e := *o.Event
		e.Start, e.End = o.Start, o.End
		return describeWhen(e, loc, h24)
	},
	"reminders": func() any { return reminderChoices },
	"reminderLabel": func(m int) string {
		for _, c := range reminderChoices {
			if c.Minutes == m {
				return c.Label
			}
		}
		return strconv.Itoa(m) + " minutes before"
	},
	"statusLabel": func(s string) string { return Attendee{Status: s}.StatusLabel() },
	"statusClass": func(s string) string { return Attendee{Status: s}.StatusClass() },
	"dueLabel": func(due, today time.Time) string {
		switch days := int(due.Sub(today).Hours() / 24); {
		case days == 0:
			return "today"
		case days == 1:
			return "tomorrow"
		case days == -1:
			return "yesterday"
		case days > 1 && days < 7:
			return due.Format("Monday")
		case due.Year() == today.Year():
			return due.Format("Jan 2")
		}
		return due.Format("Jan 2, 2006")
	},
	"add":        func(a, b int) int { return a + b },
	"initials":   initials,
	"addrOf":     func(email string) []Address { return []Address{{Email: email}} },
	"formatAddr": func(name, email string) string { return formatAddress(Address{Name: name, Email: email}) },
	"authChecks": parseAuthResults,
	"depthClass": func(depth int) string { return "depth-" + strconv.Itoa(min(depth, 5)) },
	"tagClass":   tagClass,
	"join":       strings.Join,
	"linkify":    linkify,
	"pageSizes":  func() []int { return []int{25, 50, 100, 200} },
	"countable":  countable,
	"showCount":  func(f Folder) bool { return f.Unread > 0 && countable(f) },
	"roleName": func(name string, folders []Folder) string {
		for _, f := range folders {
			if f.Name == name {
				return string(f.Role)
			}
		}
		return ""
	},
	"isRole": func(name string, folders []Folder, role string) bool {
		for _, f := range folders {
			if f.Name == name {
				return string(f.Role) == role
			}
		}
		return false
	},
	"folderLabel": func(name string, folders []Folder) string {
		for _, f := range folders {
			if f.Name == name {
				return f.Display
			}
		}
		return name
	},
}

// option is a value and label for a select.
type option struct{ Value, Label string }

// countable reports whether a folder's unread count means anything to the
// user. Unread mail in Sent, Drafts, Junk or Trash isn't waiting for them.
func countable(f Folder) bool {
	return f.Role != RoleSent && f.Role != RoleTrash && f.Role != RoleDrafts && f.Role != RoleJunk
}

// tagClass gives each tag one of eight colours, the same one everywhere it
// appears, derived from its name.
func tagClass(tag string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(tag)))
	return "tag-" + strconv.Itoa(int(h.Sum32()%8))
}

var linkRE = regexp.MustCompile(`https?://[^\s<>"']+[^\s<>"'.,;:!?)\]]`)

// linkify escapes plain text and turns the web links in it into anchors that
// open in a new tab without a referrer. Only http and https are linked, so a
// message can't plant a javascript: link.
func linkify(text string) template.HTML {
	var b strings.Builder
	last := 0
	for _, m := range linkRE.FindAllStringIndex(text, -1) {
		b.WriteString(template.HTMLEscapeString(text[last:m[0]]))
		u := text[m[0]:m[1]]
		esc := template.HTMLEscapeString(u)
		b.WriteString(`<a href="` + esc + `" rel="noopener noreferrer" target="_blank">` + esc + `</a>`)
		last = m[1]
	}
	b.WriteString(template.HTMLEscapeString(text[last:]))
	// #nosec G203 -- every piece of text is escaped above; only the anchors are markup
	return template.HTML(b.String())
}

func folderURL(folder string, page int, query string) string {
	v := url.Values{"f": {folder}}
	if page > 1 {
		v.Set("page", strconv.Itoa(page))
	}
	if query != "" {
		v.Set("q", query)
	}
	return "/mail?" + v.Encode()
}

func messageURL(folder string, uid uint32, page int, query string) string {
	return folderURL(folder, page, query) + "&uid=" + strconv.FormatUint(uint64(uid), 10)
}

// shortDate is the message-list date: a time for today, a day for this
// year, a full date for anything older, all in the user's time zone.
func shortDate(loc *time.Location, h24 bool, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	now := time.Now().In(loc)
	switch {
	case t.Year() == now.Year() && t.YearDay() == now.YearDay():
		return clock(h24, t)
	case t.Year() == now.Year():
		return t.Format("Jan 2")
	default:
		return t.Format("2006-01-02")
	}
}

func longDate(loc *time.Location, h24 bool, t time.Time) string {
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	return t.Format("Mon Jan 2, 2006") + " " + clock(h24, t)
}

// clock formats a time of day as 15:04 or 3:04 PM.
func clock(h24 bool, t time.Time) string {
	if h24 {
		return t.Format("15:04")
	}
	return t.Format("3:04 PM")
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func joinAddresses(list []Address) string {
	labels := make([]string, 0, len(list))
	for _, a := range list {
		labels = append(labels, a.Label())
	}
	return strings.Join(labels, ", ")
}

func initials(list []Address) string {
	if len(list) == 0 {
		return "?"
	}
	words := strings.Fields(list[0].Label())
	var b strings.Builder
	for _, w := range words {
		r := []rune(w)
		if len(r) > 0 && b.Len() < 2 {
			b.WriteString(strings.ToUpper(string(r[0])))
		}
	}
	if b.Len() == 0 {
		return "?"
	}
	return b.String()
}

// AuthCheck is one result from an Authentication-Results header.
type AuthCheck struct {
	Method string
	Result string
	Pass   bool
}

var authResultRE = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc|arc)=([a-z]+)`)

// parseAuthResults pulls the method=result pairs worth showing a user out of
// an Authentication-Results header. Only the first result per method counts.
func parseAuthResults(header string) []AuthCheck {
	var out []AuthCheck
	seen := map[string]bool{}
	for _, m := range authResultRE.FindAllStringSubmatch(header, -1) {
		method := strings.ToUpper(m[1])
		if seen[method] {
			continue
		}
		seen[method] = true
		res := strings.ToLower(m[2])
		out = append(out, AuthCheck{Method: method, Result: res, Pass: res == "pass"})
	}
	return out
}
