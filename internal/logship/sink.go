package logship

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

const (
	sendTimeout     = 20 * time.Second
	maxAnswerBytes  = 8 << 20
	maxReasonLength = 300

	templatePriority = 500
)

// Credential is how the console signs in to the destination: an API key, or
// a user name and password.
type Credential struct {
	APIKey   string `json:"api_key,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (c Credential) set() bool { return c.APIKey != "" || c.Username != "" }

func (c Credential) valid() error {
	for _, v := range []string{c.APIKey, c.Username, c.Password} {
		if len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
			return errors.New("a credential is at most 1024 characters, on one line")
		}
	}
	if c.APIKey != "" && (c.Username != "" || c.Password != "") {
		return errors.New("use an API key or a user name and password, not both")
	}
	if c.Password != "" && c.Username == "" {
		return errors.New("a password needs a user name")
	}
	return nil
}

type entry struct {
	streamID string
	id       string
	doc      map[string]any
	at       time.Time
}

func newEntry(streamID, service, host, line string, queued time.Time) entry {
	doc, at := document(service, host, []byte(line), queued)
	// From the content as well as the stream's id, which starts again if
	// Valkey loses its data.
	sum := sha256.Sum256([]byte(streamID + "\x00" + service + "\x00" + host + "\x00" + line))
	return entry{streamID: streamID, id: hex.EncodeToString(sum[:16]), doc: doc, at: at}
}

type delivery struct {
	done     []string // to take off the stream
	sent     int
	rejected int
	reason   string
}

type sink struct {
	// base is the operator's copy of the destination, never settings.URL,
	// which came in a request.
	base       string
	settings   Settings
	credential Credential
	http       *http.Client
	templated  bool
}

func newSink(base string, s Settings, c Credential) *sink {
	dialer := &net.Dialer{Timeout: sendTimeout, Control: checkDestination}
	transport := &http.Transport{
		Proxy:               nil, // never an environment proxy: it would dial for us, unchecked
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: sendTimeout,
		IdleConnTimeout:     30 * time.Second,
	}
	return &sink{base: base, settings: s, credential: c, http: &http.Client{
		Timeout:   sendTimeout,
		Transport: transport,
		// A redirect would take the credential somewhere nobody chose.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

var errDestination = errors.New("logs can't be sent to link-local, cloud metadata, multicast or unspecified addresses")

// Cloud metadata services that aren't at a link-local address.
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}

// checkDestination runs on every connection, after the name is resolved. A
// log cluster is usually on a private network, so those are allowed; an
// instance's metadata, which hands out the machine's credentials, never is.
func checkDestination(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errDestination
	}
	ip := ap.Addr().Unmap().WithZone("")
	if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return errDestination
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return errDestination
		}
	}
	return nil
}

func (s *sink) post(ctx context.Context, method, path, kind string, body []byte) (int, []byte, error) {
	// #nosec G704 -- base is from the operator's list in the environment
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", kind)
	switch {
	case s.credential.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+s.credential.APIKey)
	case s.credential.Username != "":
		req.SetBasicAuth(s.credential.Username, s.credential.Password)
	}
	resp, err := s.http.Do(req) // #nosec G704 -- see above
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	return resp.StatusCode, data, err
}

// refusal words an error answer. Only Elasticsearch's own reason is quoted:
// the body of whatever else a URL points at is nobody's to read through here.
func refusal(doing string, status int, body []byte) error {
	var e struct {
		Error struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"error"`
	}
	msg := fmt.Sprintf("%s: HTTP %d", doing, status)
	if json.Unmarshal(body, &e) == nil && e.Error.Type != "" {
		msg += " " + clip(e.Error.Type+": "+e.Error.Reason)
	}
	return errors.New(msg)
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if len(s) > maxReasonLength {
		s = strings.ToValidUTF8(s[:maxReasonLength], "")
	}
	return s
}

func template(prefix, policy string) ([]byte, error) {
	type m = map[string]any
	keyword := m{"type": "keyword", "ignore_above": 1024}
	tmpl := m{
		"index_patterns": []string{prefix + "-*"},
		// Above the broad elemta-* template of the development overlay, and
		// higher the longer the prefix: elemta-logs-* also covers
		// elemta-logs-prod-*, and Elasticsearch refuses two templates that
		// overlap at one priority.
		"priority": templatePriority + len(prefix),
		"_meta":    m{"description": "Elemta service logs"},
		"template": m{
			"mappings": m{
				"dynamic": false,
				"properties": m{
					"@timestamp": m{"type": "date"},
					"message":    m{"type": "text", "fields": m{"keyword": m{"type": "keyword", "ignore_above": 512}}},
					"log":        m{"properties": m{"level": keyword}},
					"service":    m{"properties": m{"name": keyword}},
					"host":       m{"properties": m{"name": keyword}},
					"event":      m{"properties": m{"action": keyword}},
					"source":     m{"properties": m{"ip": m{"type": "ip", "ignore_malformed": true}}},
					"elemta":     m{"type": "flattened", "ignore_above": 4096},
				},
			},
		},
	}
	// One replica where there is a second node to hold it, none on a single
	// node. The default of 1 can never be placed on one node: the cluster
	// stays yellow and ILM's warm phase waits for that copy forever, so a
	// delete phase never runs. Logs are a copy of what the services wrote,
	// so more than one replica isn't worth the disk.
	index := m{"auto_expand_replicas": "0-1"}
	// The template is written again whenever the shipper starts, so a policy
	// set on it by hand would be lost; it has to come from the settings.
	// Without one it is left out, so the template still matches
	// deployments/elk/logs-template.json, which Logstash installs.
	if policy != "" {
		index["lifecycle"] = m{"name": policy}
	}
	tmpl["template"].(m)["settings"] = m{"index": index}
	return json.Marshal(tmpl)
}

func (s *sink) send(ctx context.Context, batch []entry) (delivery, error) {
	if s.settings.Kind == KindLogstash {
		return s.sendLogstash(ctx, batch)
	}
	return s.sendElasticsearch(ctx, batch)
}

func (s *sink) sendLogstash(ctx context.Context, batch []entry) (delivery, error) {
	var out delivery
	docs := make([]map[string]any, len(batch))
	for i, e := range batch {
		d := maps.Clone(e.doc)
		d["log_id"] = e.id
		d["index_prefix"] = s.settings.Index
		docs[i] = d
	}
	body, err := json.Marshal(docs)
	if err != nil {
		return out, err
	}
	status, answer, err := s.post(ctx, http.MethodPost, "", "application/json", body)
	if err != nil {
		return out, err
	}
	if status < 200 || status > 299 {
		return out, refusal("Logstash didn't take the logs", status, answer)
	}
	for _, e := range batch {
		out.done = append(out.done, e.streamID)
	}
	out.sent = len(batch)
	return out, nil
}

func (s *sink) sendElasticsearch(ctx context.Context, batch []entry) (delivery, error) {
	var out delivery
	if !s.templated {
		// Before the first document: an index made without it maps fields by
		// whatever line came first, and that can't be changed afterwards.
		body, err := template(s.settings.Index, s.settings.LifecyclePolicy)
		if err != nil {
			return out, err
		}
		status, answer, err := s.post(ctx, http.MethodPut, "/_index_template/"+s.settings.Index, "application/json", body)
		if err != nil {
			return out, err
		}
		if status < 200 || status > 299 {
			doing := "the index template couldn't be saved"
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				doing += " (check the credential, and that it has manage_index_templates)"
			}
			return out, refusal(doing, status, answer)
		}
		s.templated = true
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range batch {
		// create, so a batch sent again doesn't double anything.
		action := map[string]any{"create": map[string]string{"_index": s.settings.Index + "-" + e.at.Format("2006.01.02"), "_id": e.id}}
		if err := enc.Encode(action); err != nil {
			return out, err
		}
		if err := enc.Encode(e.doc); err != nil {
			return out, err
		}
	}
	status, answer, err := s.post(ctx, http.MethodPost, "/_bulk?filter_path=errors,items.*.status,items.*.error.type,items.*.error.reason", "application/x-ndjson", body.Bytes())
	if err != nil {
		return out, err
	}
	if status < 200 || status > 299 {
		return out, refusal("Elasticsearch didn't take the logs", status, answer)
	}
	var result struct {
		Items []map[string]struct {
			Status int `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(answer, &result); err != nil || len(result.Items) != len(batch) {
		return out, errors.New("the answer wasn't Elasticsearch's: check the URL")
	}
	var retry error
	for i, item := range result.Items {
		r := item["create"]
		switch {
		case r.Status >= 200 && r.Status < 300, r.Status == http.StatusConflict: // 409: sent before
			out.done = append(out.done, batch[i].streamID)
			out.sent++
		case r.Status == http.StatusBadRequest:
			// It will never be taken, and mustn't hold up the rest.
			out.done = append(out.done, batch[i].streamID)
			out.rejected++
			out.reason = clip(r.Error.Type + ": " + r.Error.Reason)
		default:
			retry = fmt.Errorf("Elasticsearch will be retried: HTTP %d %s", r.Status, clip(r.Error.Type+": "+r.Error.Reason)) //nolint:staticcheck // a product name
		}
	}
	return out, retry
}
