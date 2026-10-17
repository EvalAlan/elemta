package webmail

import (
	"embed"
	"fmt"
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

// pages are the templates rendered inside layout.html. login.html stands
// alone because it has no folder tree.
var pages = []string{"mail.html", "compose.html", "error.html"}

func loadTemplates() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, p := range pages {
		t, err := template.New("layout.html").Funcs(templateFuncs).ParseFS(templateFS, "templates/layout.html", "templates/icons.html", "templates/"+p)
		if err != nil {
			return nil, fmt.Errorf("webmail: template %s: %w", p, err)
		}
		out[p] = t
	}
	t, err := template.New("login.html").Funcs(templateFuncs).ParseFS(templateFS, "templates/login.html", "templates/icons.html")
	if err != nil {
		return nil, fmt.Errorf("webmail: template login.html: %w", err)
	}
	out["login.html"] = t
	return out, nil
}

var templateFuncs = template.FuncMap{
	"shortDate":  shortDate,
	"longDate":   func(t time.Time) string { return t.Local().Format("Mon Jan 2, 2006 15:04") },
	"humanSize":  humanSize,
	"addrs":      joinAddresses,
	"folderURL":  folderURL,
	"messageURL": messageURL,
	"partURL": func(folder string, uid uint32, n int) string {
		return "/mail/part?" + url.Values{"f": {folder}, "uid": {strconv.FormatUint(uint64(uid), 10)}, "n": {strconv.Itoa(n)}}.Encode()
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
	"add":        func(a, b int) int { return a + b },
	"initials":   initials,
	"addrOf":     func(email string) []Address { return []Address{{Email: email}} },
	"authChecks": parseAuthResults,
	"depthClass": func(depth int) string { return "depth-" + strconv.Itoa(min(depth, 5)) },
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
// year, a full date for anything older.
func shortDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.Local()
	now := time.Now()
	switch {
	case t.Year() == now.Year() && t.YearDay() == now.YearDay():
		return t.Format("15:04")
	case t.Year() == now.Year():
		return t.Format("Jan 2")
	default:
		return t.Format("2006-01-02")
	}
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
