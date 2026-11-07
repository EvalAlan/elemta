package mailbox

// The HTTP APIs through the router.
//
// A request about one account goes to that account's cell: the webmail's
// requests (signed in as the user, HTTP Basic), and the admin console's
// requests that name an account, list or domain. Settings every cell keeps
// (classes of service) are written to every cell. Lists the console reads
// (domains, routes, lists, resources, the audit log, compliance search)
// are gathered from every cell and merged. A compliance hit's reference
// is prefixed with its cell ("cell:ref") so fetching that message goes
// back to the right one, and a compliance export streams each cell's part
// in turn (mbox files simply follow one another).
//
// An internal client may also name a cell outright with X-Elemta-Cell,
// for anything the rules above don't place.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const cellHeader = "X-Elemta-Cell"

// Requests that name what they're about in the path.
var (
	byAddressPath = regexp.MustCompile(`^/v1/admin/(?:accounts|addresses|lists)/([^/]+)`)
	byDomainPath  = regexp.MustCompile(`^/v1/(?:admin/(?:domains|routes|domain-status)|pgp/wkd)/([^/]+)`)
	everyCellPath = regexp.MustCompile(`^/v1/admin/classes/[^/]+$`)
	gatheredPaths = map[string]bool{
		"GET /v1/admin/domains": true, "GET /v1/admin/routes": true, "GET /v1/admin/domain-status": true,
		"GET /v1/admin/lists": true, "GET /v1/admin/audit": true, "POST /v1/admin/compliance/search": true,
	}
)

func (r *Router) httpServer() *http.Server {
	proxies := map[string]*httputil.ReverseProxy{}
	for name, cell := range r.cells {
		target, err := url.Parse(cell.HTTP)
		if err != nil || cell.HTTP == "" {
			continue
		}
		p := httputil.NewSingleHostReverseProxy(target)
		p.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
			r.log.Warn("router: a cell's HTTP API", "cell", name, "path", req.URL.Path, "error", err)
			writeAdminError(w, http.StatusBadGateway, "mailbox cell unavailable")
		}
		proxies[name] = p
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if !r.isInternal(remoteAddr(req)) {
			writeAdminError(w, http.StatusForbidden, "forbidden")
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Minute)
		defer cancel()
		req = req.WithContext(ctx)
		route := req.Method + " " + req.URL.Path
		switch {
		case everyCellPath.MatchString(req.URL.Path) && req.Method != http.MethodGet:
			r.toEveryCell(w, req)
			return
		case gatheredPaths[route] || (route == "GET /v1/admin/resources" && req.URL.Query().Get("domain") == ""):
			r.gather(w, req)
			return
		case route == "POST /v1/admin/compliance/export":
			r.exportEveryCell(w, req)
			return
		}
		cell, err := r.httpCell(ctx, req)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, errNoCell) {
				status = http.StatusBadRequest
			}
			writeAdminError(w, status, err.Error())
			return
		}
		p := proxies[cell.Name]
		if p == nil {
			writeAdminError(w, http.StatusBadGateway, "cell "+cell.Name+" has no HTTP address")
			return
		}
		p.ServeHTTP(w, req)
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}

func remoteAddr(req *http.Request) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", req.RemoteAddr)
	if err != nil {
		return nil
	}
	return a
}

// httpCell finds the one cell a request is for.
func (r *Router) httpCell(ctx context.Context, req *http.Request) (*routerCell, error) {
	if name := req.Header.Get(cellHeader); name != "" {
		if cell := r.cells[name]; cell != nil {
			return cell, nil
		}
		return nil, errNoCell
	}
	if user, _, ok := req.BasicAuth(); ok && user != "" {
		return r.cellFor(ctx, user)
	}
	if m := byAddressPath.FindStringSubmatch(req.URL.Path); m != nil {
		address, _ := url.PathUnescape(m[1])
		return r.cellFor(ctx, address)
	}
	if m := byDomainPath.FindStringSubmatch(req.URL.Path); m != nil {
		domain, _ := url.PathUnescape(m[1])
		return r.cellFor(ctx, "@"+domain)
	}
	q := req.URL.Query()
	if ref := q.Get("ref"); req.URL.Path == "/v1/admin/compliance/message" && ref != "" {
		name, rest, ok := strings.Cut(ref, ":")
		cell := r.cells[name]
		if !ok || cell == nil {
			return nil, errNoCell
		}
		q.Set("ref", rest)
		req.URL.RawQuery = q.Encode()
		return cell, nil
	}
	for _, key := range []string{"address", "member"} {
		if a := q.Get(key); a != "" {
			return r.cellFor(ctx, a)
		}
	}
	if d := q.Get("domain"); d != "" {
		return r.cellFor(ctx, "@"+d)
	}
	return r.cells[r.cfg.Router.DefaultCell], nil
}

// cellResponse is one cell's answer to a request sent to several.
type cellResponse struct {
	cell   string
	status int
	header http.Header
	body   []byte
	err    error
}

// each sends req to every cell at once, its body copied for each.
func (r *Router) each(req *http.Request) ([]cellResponse, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(r.cells))
	for name := range r.cells {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]cellResponse, len(names))
	done := make(chan struct{}, len(names))
	for i, name := range names {
		go func(i int, cell *routerCell) {
			defer func() { done <- struct{}{} }()
			out[i] = r.send(req, cell, body)
		}(i, r.cells[name])
	}
	for range names {
		<-done
	}
	return out, nil
}

func (r *Router) send(req *http.Request, cell *routerCell, body []byte) cellResponse {
	res := cellResponse{cell: cell.Name}
	out, err := r.cellRequest(req, cell, body)
	if err != nil {
		res.err = err
		return res
	}
	resp, err := http.DefaultClient.Do(out) // #nosec G704 -- built by cellRequest from operator configuration
	if err != nil {
		res.err = err
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.status, res.header = resp.StatusCode, resp.Header
	res.body, res.err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return res
}

func (r *Router) cellRequest(req *http.Request, cell *routerCell, body []byte) (*http.Request, error) {
	if cell.HTTP == "" {
		return nil, fmt.Errorf("cell %s has no HTTP address", cell.Name)
	}
	// The cell's scheme and host come from the router's configuration
	// only; the client chooses the path, which stays an API path.
	base, err := url.Parse(cell.HTTP)
	if err != nil || base.Host == "" || !strings.HasPrefix(req.URL.Path, "/v1/") {
		return nil, fmt.Errorf("cell %s: no such API path", cell.Name)
	}
	u := url.URL{Scheme: base.Scheme, Host: base.Host, Path: strings.TrimSuffix(base.Path, "/") + req.URL.Path, RawQuery: req.URL.RawQuery}
	// #nosec G704 -- scheme and host are operator configuration (the cell's http); only the /v1/ path is the client's
	out, err := http.NewRequestWithContext(req.Context(), req.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, h := range []string{"Authorization", "Content-Type", "Accept"} {
		if v := req.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	return out, nil
}

// firstFailure is the first cell that didn't succeed, if any.
func firstFailure(rs []cellResponse) *cellResponse {
	for i := range rs {
		if rs[i].err != nil || rs[i].status >= 300 {
			return &rs[i]
		}
	}
	return nil
}

func (r *Router) relayFailure(w http.ResponseWriter, f *cellResponse) {
	if f.err != nil {
		r.log.Warn("router: a cell's HTTP API", "cell", f.cell, "error", f.err)
		writeAdminError(w, http.StatusBadGateway, "mailbox cell "+f.cell+" unavailable")
		return
	}
	w.Header().Set("Content-Type", f.header.Get("Content-Type"))
	w.WriteHeader(f.status)
	_, _ = w.Write(f.body)
}

// toEveryCell writes a setting every cell keeps.
func (r *Router) toEveryCell(w http.ResponseWriter, req *http.Request) {
	rs, err := r.each(req)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "unreadable request")
		return
	}
	if f := firstFailure(rs); f != nil {
		r.relayFailure(w, f)
		return
	}
	w.Header().Set("Content-Type", rs[0].header.Get("Content-Type"))
	w.WriteHeader(rs[0].status)
	_, _ = w.Write(rs[0].body)
}

// gather asks every cell and merges the answers: arrays are joined; in
// objects, arrays are joined and counts added. Compliance hits are marked
// with their cell.
func (r *Router) gather(w http.ResponseWriter, req *http.Request) {
	rs, err := r.each(req)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "unreadable request")
		return
	}
	if f := firstFailure(rs); f != nil {
		r.relayFailure(w, f)
		return
	}
	var merged any
	for _, res := range rs {
		var v any
		if err := json.Unmarshal(res.body, &v); err != nil {
			r.log.Warn("router: a cell's answer isn't JSON", "cell", res.cell, "path", req.URL.Path)
			writeAdminError(w, http.StatusBadGateway, "mailbox cell "+res.cell+" gave an unreadable answer")
			return
		}
		if req.URL.Path == "/v1/admin/compliance/search" {
			markRefs(v, res.cell)
		}
		merged = mergeJSON(merged, v)
	}
	if req.URL.Path == "/v1/admin/audit" {
		merged = newestFirst(merged, req.URL.Query().Get("limit"))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(merged)
}

func mergeJSON(a, b any) any {
	switch bv := b.(type) {
	case []any:
		av, _ := a.([]any)
		return append(av, bv...)
	case map[string]any:
		av, ok := a.(map[string]any)
		if !ok {
			return bv
		}
		for k, v := range bv {
			switch x := v.(type) {
			case []any:
				prev, _ := av[k].([]any)
				av[k] = append(prev, x...)
			case float64:
				prev, _ := av[k].(float64)
				av[k] = prev + x
			default:
				if _, set := av[k]; !set {
					av[k] = v
				}
			}
		}
		return av
	}
	if a == nil {
		return b
	}
	return a
}

// markRefs prefixes each compliance hit's reference with its cell.
func markRefs(v any, cell string) {
	obj, _ := v.(map[string]any)
	hits, _ := obj["hits"].([]any)
	for _, h := range hits {
		if hit, ok := h.(map[string]any); ok {
			if ref, ok := hit["ref"].(string); ok {
				hit["ref"] = cell + ":" + ref
			}
		}
	}
}

// newestFirst orders audit entries from every cell by time, and keeps as
// many as one cell would have returned.
func newestFirst(v any, limit string) any {
	entries, ok := v.([]any)
	if !ok {
		return v
	}
	at := func(e any) string { m, _ := e.(map[string]any); s, _ := m["at"].(string); return s }
	sort.SliceStable(entries, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, at(entries[i]))
		tj, _ := time.Parse(time.RFC3339Nano, at(entries[j]))
		return ti.After(tj)
	})
	if n, err := strconv.Atoi(limit); err == nil && n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// exportEveryCell streams each cell's compliance export in turn.
func (r *Router) exportEveryCell(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 64<<10))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "unreadable request")
		return
	}
	names := make([]string, 0, len(r.cells))
	for name := range r.cells {
		names = append(names, name)
	}
	sort.Strings(names)
	started := false
	for _, name := range names {
		out, err := r.cellRequest(req, r.cells[name], body)
		var resp *http.Response
		if err == nil {
			resp, err = http.DefaultClient.Do(out) // #nosec G704 -- built by cellRequest from operator configuration
		}
		if err != nil {
			r.log.Warn("router: compliance export", "cell", name, "error", err)
			if !started {
				writeAdminError(w, http.StatusBadGateway, "mailbox cell "+name+" unavailable")
			}
			return
		}
		if resp.StatusCode != http.StatusOK {
			if !started {
				w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
			} else {
				r.log.Warn("router: compliance export stopped part way", "cell", name, "status", resp.StatusCode)
			}
			_ = resp.Body.Close()
			return
		}
		if !started {
			w.Header().Set("Content-Type", "application/mbox")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			started = true
		}
		_, err = io.Copy(w, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return
		}
	}
	if !started {
		w.Header().Set("Content-Type", "application/mbox")
		w.WriteHeader(http.StatusOK)
	}
}
