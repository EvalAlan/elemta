package logship

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/stretchr/testify/require"
)

func prepared(t *testing.T, line string, p policy) string {
	t.Helper()
	if p.MinLevel == "" {
		p.MinLevel = "info"
	}
	return string(prepare([]byte(line), p, time.Now()))
}

func TestWhatNeverLeaves(t *testing.T) {
	for name, line := range map[string]string{
		"password field":     `{"msg":"x","smtp_password":"s3cret"}`,
		"nested":             `{"msg":"x","a":{"b":[{"Authorization":"s3cret"}]}}`,
		"dashed header":      `{"msg":"x","X-Api-Key":"s3cret"}`,
		"unknown verb":       `{"msg":"x","command":"s3cret"}`,
		"PASS":               `{"msg":"x","command":"PASS","parameters":"s3cret"}`,
		"AUTH":               `{"msg":"x","command":"AUTH PLAIN s3cret"}`,
		"typed line":         `{"msg":"x","original_line":"s3cret and more"}`,
		"message line":       `{"msg":"x","line":"s3cret"}`,
		"debug args":         `{"msg":"x","args":"s3cret"}`,
		"URL field":          `{"msg":"x","url":"valkey://user:s3cret@valkey:6379"}`,
		"URL in an error":    `{"msg":"x","error":"dial redis://:s3cret@valkey:6379: refused"}`,
		"URL in the message": `{"msg":"using postgres://elemta:s3cret@db/mail"}`,
		"URL in a text line": `level=INFO msg="using https://u:s3cret@es:9200"`,
		"subject":            `{"msg":"x","subject":"s3cret"}`,
		"message subject":    `{"msg":"x","message_subject":"s3cret"}`,
	} {
		got := prepared(t, line, policy{})
		require.NotEmpty(t, got, name)
		require.NotContains(t, got, "s3cret", name)
	}
}

func TestWhatDoesLeave(t *testing.T) {
	got := prepared(t, `{"msg":"ok","command":"RCPT TO:<dana@example.com>","has_password":true,"subject":"Lunch"}`, policy{IncludeSubjects: true})
	for _, want := range []string{"RCPT TO:", "dana@example.com", `"has_password":true`, "Lunch"} {
		require.Contains(t, got, want)
	}
	require.Empty(t, prepared(t, `{"level":"DEBUG","msg":"noise"}`, policy{}))
	require.Empty(t, prepared(t, `{"level":"INFO","msg":"noise"}`, policy{MinLevel: "warn"}))
	require.NotEmpty(t, prepared(t, `time=x level=ERROR msg="from a text logger"`, policy{MinLevel: "error"}))

	long, err := json.Marshal(map[string]string{"msg": strings.Repeat("é", 4000), "error": strings.Repeat("x", 9000)})
	require.NoError(t, err)
	got = prepared(t, string(long), policy{})
	require.LessOrEqual(t, len(got), maxLineBytes)
	require.True(t, json.Valid([]byte(got)))
	require.Contains(t, got, `"truncated":true`)
}

func TestDocument(t *testing.T) {
	doc, at := document("mailbox", "box-1", []byte(`{"time":"2026-11-22T10:00:00+02:00","level":"WARN","msg":"hello","service":"imap","event_type":"auth","remote_addr":"[2001:db8::1]:993","imap":{"addr":":993"}}`), time.Now())
	require.Equal(t, "2026-11-22T08:00:00Z", at.Format(time.RFC3339))
	require.Equal(t, "hello", doc["message"])
	require.Equal(t, map[string]any{"name": "mailbox"}, doc["service"])
	require.Equal(t, map[string]any{"level": "warn"}, doc["log"])
	require.Equal(t, map[string]any{"ip": "2001:db8::1"}, doc["source"])
	// The line's own "service" can't collide with service.name here.
	require.Equal(t, "imap", doc["elemta"].(map[string]any)["service"])
}

func TestSettings(t *testing.T) {
	good := Settings{Enabled: true, URL: "https://es.example.com:9200"}
	require.NoError(t, good.WithDefaults().Validate())
	for name, s := range map[string]Settings{
		"no URL":         {Enabled: true},
		"password":       {URL: "https://u:p@es.example.com"},
		"scheme":         {URL: "file:///etc/passwd"},
		"query":          {URL: "https://es.example.com?x=1"},
		"index traverse": {URL: good.URL, Index: "../_security"},
		"level":          {URL: good.URL, MinLevel: "loud"},
		"kind":           {URL: good.URL, Kind: "syslog"},
	} {
		require.Error(t, s.WithDefaults().Validate(), name)
	}
}

func TestCredentialStaysWithItsDestination(t *testing.T) {
	dir := t.TempDir()
	var got string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer other.Close()
	s := NewShipper(dir, "", []string{"https://es.example.com:9200", other.URL}, nil)
	ctx := context.Background()
	require.NoError(t, s.Save(ctx, Settings{URL: "https://es.example.com:9200"}, &Credential{APIKey: "k3y"}))
	info, err := os.Stat(filepath.Join(dir, fileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	require.NoError(t, s.Save(ctx, Settings{URL: "https://es.example.com:9200", MinLevel: "warn"}, nil))
	_, set, err := s.Settings()
	require.NoError(t, err)
	require.True(t, set, "an edit lost the credential")

	require.NoError(t, s.Test(ctx, Settings{URL: other.URL, Kind: KindLogstash}, nil))
	require.Empty(t, got, "the credential went to another host")

	require.NoError(t, s.Save(ctx, Settings{URL: other.URL}, nil))
	_, set, err = s.Settings()
	require.NoError(t, err)
	require.False(t, set, "the credential followed the URL")
}

// fakeES takes documents as Elasticsearch does.
type fakeES struct {
	mu     sync.Mutex
	down   bool
	status map[string]int // by message
	calls  []string
	docs   map[string]map[string]any
}

func (f *fakeES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "a page that mustn't be quoted")
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Method == http.MethodPut {
		_, _ = io.WriteString(w, `{"acknowledged":true}`)
		return
	}
	items := []any{}
	lines := bufio.NewScanner(r.Body)
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var action map[string]map[string]string
		if json.Unmarshal(lines.Bytes(), &action) != nil || !lines.Scan() {
			break
		}
		var doc map[string]any
		if json.Unmarshal(lines.Bytes(), &doc) != nil {
			break
		}
		id, status := action["create"]["_id"], http.StatusCreated
		msg, _ := doc["message"].(string)
		if s := f.status[msg]; s != 0 {
			status = s
		} else if _, ok := f.docs[id]; ok {
			status = http.StatusConflict
		} else {
			f.docs[id] = doc
		}
		items = append(items, map[string]any{"create": map[string]any{"status": status, "error": map[string]string{"type": "t", "reason": "r"}}})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

func TestElasticsearch(t *testing.T) {
	es := &fakeES{status: map[string]int{"bad": 400, "busy": 429}, docs: map[string]map[string]any{}}
	srv := httptest.NewServer(es)
	defer srv.Close()
	now := time.Now()
	batch := []entry{}
	for i, msg := range []string{"good", "bad", "busy", "also good"} {
		batch = append(batch, newEntry(string(rune('a'+i)), "mta", "h", `{"msg":"`+msg+`"}`, now))
	}
	s := newSink(srv.URL, Settings{}.WithDefaults(), Credential{})
	out, err := s.send(context.Background(), batch)
	require.Error(t, err, "a 429 has to be retried")
	require.Equal(t, []string{"a", "b", "d"}, out.done)
	require.Equal(t, 2, out.sent)
	require.Equal(t, 1, out.rejected)
	require.Equal(t, []string{"PUT /_index_template/elemta-logs", "POST /_bulk"}, es.calls, "the template goes first")

	_, _ = s.send(context.Background(), batch)
	require.Len(t, es.docs, 2, "sending again doubled a line")

	es.down = true
	_, err = s.send(context.Background(), batch)
	require.ErrorContains(t, err, "503")
	require.NotContains(t, err.Error(), "quoted")
}

func TestRedirectIsNotFollowed(t *testing.T) {
	followed := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer other.Close()
	srv := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusTemporaryRedirect))
	defer srv.Close()
	s := newSink(srv.URL, Settings{Kind: KindLogstash}.WithDefaults(), Credential{Username: "u", Password: "p"})
	_, err := s.send(context.Background(), []entry{newEntry("1", "mta", "h", `{"msg":"x"}`, time.Now())})
	require.Error(t, err)
	require.False(t, followed)
}

func TestLoggingNeverWaits(t *testing.T) {
	c := newCollector("mta", "unused")
	for range collectQueue + 10 {
		c.offer([]byte(`{"msg":"x"}`))
	}
	require.EqualValues(t, 10, c.dropped.Load())
}

// The whole path over a real Valkey, an outage included.
func TestPipeline(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY")
	if addr == "" {
		t.Skip("set ELEMTA_TEST_VALKEY")
	}
	ctx := context.Background()
	client, err := valkeyaddr.NewClient(addr, nil)
	require.NoError(t, err)
	clean := func() {
		_ = client.Do(ctx, client.B().Del().Key(keyPolicy, keyStream, keyStatus, keyLock).Build()).Error()
	}
	clean()
	t.Cleanup(func() { clean(); client.Close() })

	es := &fakeES{down: true, docs: map[string]map[string]any{}}
	srv := httptest.NewServer(es)
	defer srv.Close()
	s := NewShipper(t.TempDir(), addr, []string{srv.URL}, nil)
	set := Settings{Enabled: true, URL: srv.URL}.WithDefaults()
	require.NoError(t, s.Save(ctx, set, nil))

	for _, service := range []string{"mta", "admin", "webmail", "mailbox"} {
		c := newCollector(service, addr)
		c.offer([]byte(`{"msg":"before the first answer","level":"INFO"}`))
		c.readPolicy(ctx)
		c.offer([]byte(`{"msg":"after","password":"s3cret"}`))
		c.flush(ctx)
		c.client.Close()
	}
	out := newSink(srv.URL, set, Credential{})
	require.Error(t, s.ship(ctx, client, out))
	st, err := s.Status(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 8, st.Waiting)
	require.NotNil(t, st.FailingSince)

	es.mu.Lock()
	es.down = false
	es.mu.Unlock()
	require.NoError(t, s.ship(ctx, client, out))
	st, err = s.Status(ctx)
	require.NoError(t, err)
	require.Zero(t, st.Waiting)
	require.EqualValues(t, 8, st.Sent)
	require.Nil(t, st.FailingSince)
	require.Len(t, es.docs, 8)
	all, err := json.Marshal(es.docs)
	require.NoError(t, err)
	require.NotContains(t, string(all), "s3cret")

	set.Enabled = false
	require.NoError(t, s.Save(ctx, set, nil))
	c := newCollector("mta", addr)
	c.readPolicy(ctx)
	defer c.client.Close()
	c.offer([]byte(`{"msg":"while off"}`))
	c.flush(ctx)
	n, err := client.Do(ctx, client.B().Xlen().Key(keyStream).Build()).AsInt64()
	require.NoError(t, err)
	require.Zero(t, n)
}

// Logstash installs the template from a file; it has to be this one.
func TestLogstashTemplateIsTheSame(t *testing.T) {
	want, err := template(DefaultIndex)
	require.NoError(t, err)
	got, err := os.ReadFile("../../deployments/elk/logs-template.json")
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(got))
}

func TestOverlappingPrefixesGetTheirOwnPriority(t *testing.T) {
	priority := func(prefix string) float64 {
		raw, err := template(prefix)
		require.NoError(t, err)
		var body struct {
			Priority float64 `json:"priority"`
		}
		require.NoError(t, json.Unmarshal(raw, &body))
		return body.Priority
	}
	require.Greater(t, priority("elemta-logs-prod"), priority("elemta-logs"), "the narrower pattern has to win")
}

func TestOnlyAPermissionProblemBlamesPermissions(t *testing.T) {
	for status, blamed := range map[int]bool{400: false, 401: true, 403: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		_, err := newSink(srv.URL, Settings{}.WithDefaults(), Credential{}).send(context.Background(), []entry{newEntry("1", "mta", "h", `{"msg":"x"}`, time.Now())})
		srv.Close()
		require.Error(t, err)
		require.Equal(t, blamed, strings.Contains(err.Error(), "manage_index_templates"), status)
	}
}

func TestDestinationsRefused(t *testing.T) {
	for _, addr := range []string{"169.254.169.254:80", "[::ffff:169.254.169.254]:80", "[fe80::1%eth0]:80", "[fd00:ec2::254]:80", "100.100.100.200:80", "0.0.0.0:9200", "[::]:9200", "224.0.0.1:80"} {
		require.ErrorIs(t, checkDestination("tcp", addr, nil), errDestination, addr)
	}
	for _, addr := range []string{"127.0.0.1:9200", "10.0.0.5:9200", "[fd12::5]:9200", "203.0.113.4:443"} {
		require.NoError(t, checkDestination("tcp", addr, nil), addr)
	}
	// Listed or not.
	err := NewShipper(t.TempDir(), "", []string{"http://169.254.169.254"}, nil).Test(context.Background(), Settings{URL: "http://169.254.169.254"}, nil)
	require.ErrorIs(t, err, errDestination)
}

func TestParseDestinations(t *testing.T) {
	got, unusable := ParseDestinations(" https://es.example.com:9200/,http://10.0.0.5:8080\nhttps://es.example.com:9200 https://u:p@x.example.com file:///etc/passwd ")
	require.Equal(t, []string{"https://es.example.com:9200", "http://10.0.0.5:8080"}, got)
	require.Equal(t, 2, unusable)
	got, unusable = ParseDestinations("")
	require.Empty(t, got)
	require.Zero(t, unusable)
}

func TestOnlyListedDestinations(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	ctx := context.Background()
	listed := srv.URL + "/in"
	s := NewShipper(t.TempDir(), "unused", []string{listed}, nil)

	for name, url := range map[string]string{
		"another host":   "https://attacker.example.net",
		"same host":      srv.URL,
		"another path":   srv.URL + "/other",
		"climbing out":   listed + "/../other",
		"longer":         listed + "side",
		"encoded":        srv.URL + "/%69n",
		"another scheme": strings.Replace(listed, "http:", "https:", 1),
		"nothing":        "",
	} {
		err := s.Test(ctx, Settings{Kind: KindLogstash, URL: url}, nil)
		require.True(t, IsInvalid(err), name)
		require.True(t, IsInvalid(s.Save(ctx, Settings{Enabled: true, Kind: KindLogstash, URL: url}, nil)), name)
	}
	require.Zero(t, hits.Load(), "a request was made to somewhere unlisted")

	require.NoError(t, s.Test(ctx, Settings{Kind: KindLogstash, URL: listed + "/"}, nil))
	require.EqualValues(t, 1, hits.Load())

	_, err := NewShipper(t.TempDir(), "", nil, nil).approved(listed)
	require.Error(t, err, "no list has to mean nowhere")
}

// A file saved under an older list, or written some other way.
func TestRunKeepsToTheList(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY")
	if addr == "" {
		t.Skip("set ELEMTA_TEST_VALKEY")
	}
	ctx := context.Background()
	client, err := valkeyaddr.NewClient(addr, nil)
	require.NoError(t, err)
	clean := func() {
		_ = client.Do(ctx, client.B().Del().Key(keyPolicy, keyStream, keyStatus, keyLock).Build()).Error()
	}
	clean()
	t.Cleanup(func() { clean(); client.Close() })
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()

	dir := t.TempDir()
	set := Settings{Enabled: true, Kind: KindLogstash, URL: srv.URL}.WithDefaults()
	require.NoError(t, NewShipper(dir, addr, []string{srv.URL}, nil).Save(ctx, set, nil))
	require.NoError(t, client.Do(ctx, client.B().Xadd().Key(keyStream).Id("*").FieldValue().
		FieldValue("s", "mta").FieldValue("h", "h").FieldValue("e", `{"msg":"x"}`).Build()).Error())

	s := NewShipper(dir, addr, nil, nil)
	run, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.Run(run) }()
	defer func() { stop(); <-done }()
	require.Eventually(t, func() bool {
		h, err := client.Do(ctx, client.B().Hgetall().Key(keyStatus).Build()).AsStrMap()
		return err == nil && strings.Contains(h["last_error"], DestinationsEnv) && h["failing_since"] != ""
	}, 10*time.Second, 50*time.Millisecond)
	require.Zero(t, hits.Load())

	set.Enabled = false
	require.NoError(t, NewShipper(dir, addr, nil, nil).Save(ctx, set, nil), "switching off has to work without a list")
}
