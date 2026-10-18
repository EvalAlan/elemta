package webmail

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeSieveServer speaks enough ManageSieve to exercise the client:
// AUTHENTICATE PLAIN, LISTSCRIPTS, GETSCRIPT, PUTSCRIPT (with literals),
// SETACTIVE and LOGOUT.
func fakeSieveServer(t *testing.T) (string, map[string]string, *string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	scripts := map[string]string{"other": "keep;"}
	active := "other"
	var mu sync.Mutex
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				w := func(s string) { _, _ = io.WriteString(c, s) }
				w("\"IMPLEMENTATION\" \"fake\"\r\n\"SASL\" \"PLAIN\"\r\nOK \"ready\"\r\n")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					mu.Lock()
					switch {
					case strings.HasPrefix(line, "AUTHENTICATE"):
						arg := line[strings.LastIndex(line[:len(line)-1], `"`)+1 : len(line)-1]
						dec, _ := base64.StdEncoding.DecodeString(arg)
						if string(dec) == "\x00dana\x00secret" {
							w("OK\r\n")
						} else {
							w("NO \"Authentication failed.\"\r\n")
						}
					case line == "LISTSCRIPTS":
						for name := range scripts {
							if name == active {
								w(fmt.Sprintf("\"%s\" ACTIVE\r\n", name))
							} else {
								w(fmt.Sprintf("{%d}\r\n%s\r\n", len(name), name))
							}
						}
						w("OK\r\n")
					case strings.HasPrefix(line, "GETSCRIPT"):
						name := strings.Trim(strings.TrimPrefix(line, "GETSCRIPT "), `"`)
						s, ok := scripts[name]
						if !ok {
							w("NO (NONEXISTENT) \"No such script\"\r\n")
							break
						}
						w(fmt.Sprintf("{%d}\r\n%s\r\nOK\r\n", len(s), s))
					case strings.HasPrefix(line, "PUTSCRIPT"):
						open := strings.LastIndex(line, "{")
						n, _ := strconv.Atoi(strings.TrimSuffix(line[open+1:len(line)-1], "+"))
						name := strings.Trim(strings.TrimSpace(line[len("PUTSCRIPT "):open]), `"`)
						buf := make([]byte, n)
						_, _ = io.ReadFull(r, buf)
						_, _ = r.ReadString('\n')
						if strings.Contains(string(buf), "bogus") {
							w("NO \"line 3: unknown command 'bogus'\"\r\n")
							break
						}
						scripts[name] = string(buf)
						w("OK\r\n")
					case strings.HasPrefix(line, "SETACTIVE"):
						active = strings.Trim(strings.TrimPrefix(line, "SETACTIVE "), `"`)
						w("OK\r\n")
					case line == "LOGOUT":
						w("OK\r\n")
						mu.Unlock()
						return
					default:
						w("NO \"unknown\"\r\n")
					}
					mu.Unlock()
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), scripts, &active
}

func TestManageSieveClient(t *testing.T) {
	addr, scripts, active := fakeSieveServer(t)
	dial := ManageSieveDialer(addr, TLSModeNone, false)
	if _, err := dial(context.Background(), "dana", "wrong"); err != ErrAuthFailed {
		t.Fatalf("bad password = %v", err)
	}
	c, err := dial(context.Background(), "dana", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	script := "require \"fileinto\";\r\n# quotes \" and \\ backslashes\r\nfileinto \"Ops\";\r\n"
	if err := c.Put("elemta", script); err != nil {
		t.Fatal(err)
	}
	if err := c.Put("elemta", "bogus;"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("rejected script error = %v", err)
	}
	if err := c.SetActive("elemta"); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get("elemta")
	if err != nil || got != script {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	list, err := c.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, s := range list {
		if s.Active != (s.Name == "elemta") {
			t.Errorf("active flags = %+v", list)
		}
	}
	if *active != "elemta" || scripts["elemta"] != script {
		t.Fatal("server state wrong")
	}
	if _, err := c.Get("missing"); err != ErrNotFound {
		t.Fatalf("missing script = %v", err)
	}
}

func TestGenerateSieve(t *testing.T) {
	fs := FilterSet{
		Rules: []FilterRule{
			{Name: "Ops", Enabled: true, MatchAll: true, Conditions: []FilterCondition{{Field: "subject", Op: "contains", Value: `[ops] "urgent"`}, {Field: "from", Op: "is", Value: "alerts@example.com"}},
				Actions: []FilterAction{{Type: "fileinto", Arg: "Ops"}, {Type: "tag", Arg: "ops"}, {Type: "stop"}}},
			{Name: "Big", Enabled: true, Conditions: []FilterCondition{{Field: "size", Op: "over", Value: "10m"}, {Field: "header:X-Spam-Flag", Op: "is", Value: "YES"}},
				Actions: []FilterAction{{Type: "discard"}}},
			{Name: "Off", Enabled: false, Actions: []FilterAction{{Type: "discard"}}},
		},
		Vacation: Vacation{Enabled: true, Subject: "Away", Body: "Back Monday.\n.leading dot", Days: 3, Start: "2026-12-20", End: "2027-01-02", Aliases: "dana@old.example, nope"},
	}
	script, err := generateSieve(fs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`require ["date", "fileinto", "imap4flags", "mailbox", "relational", "vacation"];`,
		`header :contains "subject" "[ops] \"urgent\""`,
		`address :is "from" "alerts@example.com"`,
		"if allof (",
		"addflag \"ops\";\r\n  fileinto :create \"Ops\";\r\n  stop;",
		`if anyof (size :over 10M, header :is "X-Spam-Flag" "YES")`,
		`currentdate :value "ge" "date" "2026-12-20"`,
		`:addresses ["dana@old.example"]`,
		"text:\r\nBack Monday.\r\n..leading dot\r\n.\r\n",
		`exists "list-id"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "# Off") {
		t.Error("disabled rule generated")
	}
	back, ok := parseFilterScript(script)
	if !ok || len(back.Rules) != 3 || back.Rules[0].Conditions[0].Value != `[ops] "urgent"` || back.Vacation.Days != 3 {
		t.Fatalf("round trip = %+v %v", back, ok)
	}
	if _, ok := parseFilterScript("require \"fileinto\";\r\n"); ok {
		t.Error("foreign script read as ours")
	}
}

func TestFilterRuleValidation(t *testing.T) {
	bad := []FilterRule{
		{Actions: nil},
		{Conditions: []FilterCondition{{Field: "size", Op: "contains", Value: "x"}}, Actions: []FilterAction{{Type: "discard"}}},
		{Conditions: []FilterCondition{{Field: "header:Bad Name", Op: "is", Value: "x"}}, Actions: []FilterAction{{Type: "discard"}}},
		{Conditions: []FilterCondition{{Field: "subject", Op: "regex", Value: "("}}, Actions: []FilterAction{{Type: "discard"}}},
		{Actions: []FilterAction{{Type: "redirect", Arg: "a@x.example, b@x.example"}}},
		{Actions: []FilterAction{{Type: "tag", Arg: "two words"}}},
		{Conditions: []FilterCondition{{Field: "subject", Op: "is", Value: "line\nbreak"}}, Actions: []FilterAction{{Type: "discard"}}},
	}
	for i, r := range bad {
		if r.validate() == nil {
			t.Errorf("rule %d accepted: %+v", i, r)
		}
	}
}

// fakeSieve is an in-memory SieveConn for handler tests.
type fakeSieve struct {
	scripts map[string]string
	active  string
}

func (f *fakeSieve) List() ([]SieveScript, error) {
	var out []SieveScript
	for n := range f.scripts {
		out = append(out, SieveScript{Name: n, Active: n == f.active})
	}
	return out, nil
}
func (f *fakeSieve) Get(n string) (string, error) {
	s, ok := f.scripts[n]
	if !ok {
		return "", ErrNotFound
	}
	return s, nil
}
func (f *fakeSieve) Put(n, s string) error    { f.scripts[n] = s; return nil }
func (f *fakeSieve) SetActive(n string) error { f.active = n; return nil }
func (f *fakeSieve) Close() error             { return nil }

func TestFiltersPage(t *testing.T) {
	h := newHarness(t)
	fs := &fakeSieve{scripts: map[string]string{"old": "keep;"}, active: "old"}
	h.server.sieve = func(context.Context, string, string) (SieveConn, error) { return fs, nil }
	csrf := h.login()

	_, body := h.get("/filters")
	if !strings.Contains(body, "Another filter script, “old”") {
		t.Fatalf("foreign active script not mentioned:\n%s", body)
	}
	resp := h.post("/filters", url.Values{
		"csrf": {csrf}, "op": {"save"}, "idx": {"-1"}, "name": {"Receipts"}, "enabled": {"1"}, "match": {"all"},
		"cond_field": {"from", ""}, "cond_header": {"", ""}, "cond_op": {"contains", "contains"}, "cond_value": {"shop.example", ""},
		"act_type": {"fileinto", ""}, "act_folder": {"Junk", ""}, "act_arg": {"", ""},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	if fs.active != sieveScriptName || !strings.Contains(fs.scripts[sieveScriptName], `fileinto :create "Junk"`) {
		t.Fatalf("script = %q active %q", fs.scripts[sieveScriptName], fs.active)
	}
	h.post("/filters", url.Values{"csrf": {csrf}, "op": {"vacation"}, "enabled": {"1"}, "body": {"Away"}, "days": {"2"}})
	h.post("/filters", url.Values{"csrf": {csrf}, "op": {"toggle"}, "idx": {"0"}})
	set, ok := parseFilterScript(fs.scripts[sieveScriptName])
	if !ok || len(set.Rules) != 1 || set.Rules[0].Enabled || !set.Vacation.Enabled || set.Vacation.Days != 2 {
		t.Fatalf("after vacation and toggle: %+v", set)
	}
	_, body = h.get("/filters?new=1&from=priya@northwind.example")
	if !strings.Contains(body, `value="priya@northwind.example"`) {
		t.Error("filter-from-message prefill missing")
	}
	resp = h.post("/filters", url.Values{"csrf": {csrf}, "op": {"save"}, "idx": {"-1"}, "act_type": {"redirect"}, "act_arg": {"not an address"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid filter = %d", resp.StatusCode)
	}
}

func TestFiltersDisabledWithoutSieve(t *testing.T) {
	h := newHarness(t)
	h.login()
	_, body := h.get("/filters")
	if !strings.Contains(body, "no ManageSieve server configured") {
		t.Fatalf("page:\n%s", body)
	}
}
