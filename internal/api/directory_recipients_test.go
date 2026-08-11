package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/busybox42/elemta/internal/datasource"
)

// stubDirectory serves a fixed set of accounts, one page at a time, and records
// how it was asked for them.
type stubDirectory struct {
	users    []datasource.User
	err      error
	pageSize int // 0 means honour the requested page size
	calls    []int
}

func (d *stubDirectory) ListUsers(_ context.Context, _ map[string]interface{}, limit, offset int) ([]datasource.User, error) {
	if d.err != nil {
		return nil, d.err
	}
	d.calls = append(d.calls, offset)
	if d.pageSize > 0 && limit > d.pageSize {
		limit = d.pageSize
	}
	if offset >= len(d.users) {
		return nil, nil
	}
	end := offset + limit
	if end > len(d.users) {
		end = len(d.users)
	}
	return d.users[offset:end], nil
}

func getDirectoryRecipients(t *testing.T, s *Server, query string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/directory/recipients"+query, nil)
	rec := httptest.NewRecorder()
	s.handleDirectoryRecipients(rec, req)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v\n%s", err, rec.Body.String())
	}
	return rec, body
}

func TestDirectoryImportReturnsUsableRecipients(t *testing.T) {
	s := &Server{directory: &stubDirectory{users: []datasource.User{
		{Username: "amy", Email: "amy@example.com", FullName: "Amy Pond", IsActive: true},
		{Username: "gone", Email: "gone@example.com", IsActive: false},
		{Username: "rory", Email: "rory@example.com", IsActive: true},
	}}}

	rec, body := getDirectoryRecipients(t, s, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if body["available"] != true {
		t.Errorf("available = %v", body["available"])
	}
	recipients, _ := body["recipients"].([]interface{})
	if len(recipients) != 2 {
		t.Fatalf("got %d recipients, want 2: %v", len(recipients), recipients)
	}
	// The disabled account must be reported, not silently absent.
	skipped, _ := body["skipped"].([]interface{})
	if len(skipped) != 1 {
		t.Errorf("skipped = %v; the disabled account should be reported", skipped)
	}
}

// TestNoDirectoryIsAnAnswerNotAnError. Most deployments authenticate against a
// file and have nothing to import from; that must read as a normal state so the
// dashboard can explain it rather than showing a failure.
func TestNoDirectoryIsAnAnswerNotAnError(t *testing.T) {
	s := &Server{}
	rec, body := getDirectoryRecipients(t, s, "")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; an unconfigured directory is not an error", rec.Code)
	}
	if body["available"] != false {
		t.Errorf("available = %v", body["available"])
	}
	if body["reason"] == nil || body["reason"] == "" {
		t.Error("no reason given for the directory being unavailable")
	}
}

// TestUnreachableDirectoryIsNotAnEmptyList is the important one. Returning an
// empty list when the directory is down reads as "nobody works here" and
// quietly produces a campaign addressed to no one.
func TestUnreachableDirectoryIsNotAnEmptyList(t *testing.T) {
	s := &Server{directory: &stubDirectory{err: errors.New("connection refused")}}

	rec, body := getDirectoryRecipients(t, s, "")
	if rec.Code == http.StatusOK {
		t.Errorf("status = %d; a directory that could not be read must not look like a successful empty import", rec.Code)
	}
	if body["available"] != false {
		t.Errorf("available = %v", body["available"])
	}
	reason, _ := body["reason"].(string)
	if reason == "" {
		t.Error("no reason given")
	}
}

// TestDirectoryIsPagedRatherThanRequestedWholesale: directories cap how much
// they return per call, so asking once and trusting the answer silently loses
// everyone past the cap.
func TestDirectoryIsPagedRatherThanRequestedWholesale(t *testing.T) {
	var users []datasource.User
	for i := 0; i < 1200; i++ {
		users = append(users, datasource.User{
			Username: fmt.Sprintf("user%04d", i),
			Email:    fmt.Sprintf("user%04d@example.com", i),
			IsActive: true,
		})
	}
	// A directory that refuses to return more than 200 at a time.
	stub := &stubDirectory{users: users, pageSize: 200}
	s := &Server{directory: stub}

	_, body := getDirectoryRecipients(t, s, "")
	recipients, _ := body["recipients"].([]interface{})
	if len(recipients) != 1200 {
		t.Errorf("got %d recipients from a 1200-account directory; paging is losing accounts", len(recipients))
	}
	if len(stub.calls) < 2 {
		t.Errorf("directory was asked %d time(s); it must be paged", len(stub.calls))
	}
}

// TestImportStopsAtTheCapAndSaysSo: silently returning a prefix of a very large
// directory would have the operator mail some of the company believing they had
// mailed all of it.
func TestImportStopsAtTheCapAndSaysSo(t *testing.T) {
	var users []datasource.User
	for i := 0; i < 60; i++ {
		users = append(users, datasource.User{
			Username: fmt.Sprintf("u%02d", i),
			Email:    fmt.Sprintf("u%02d@example.com", i),
			IsActive: true,
		})
	}
	s := &Server{directory: &stubDirectory{users: users}}

	// Ask for fewer than exist.
	_, body := getDirectoryRecipients(t, s, "?limit=50")
	if body["truncated"] != true {
		t.Errorf("truncated = %v; an incomplete import must say so", body["truncated"])
	}
	if body["reason"] == nil {
		t.Error("a truncated import gave no explanation")
	}
	recipients, _ := body["recipients"].([]interface{})
	if len(recipients) != 50 {
		t.Errorf("got %d recipients, want the 50 asked for", len(recipients))
	}
}

func TestDirectoryImportRejectsNonsenseLimit(t *testing.T) {
	s := &Server{directory: &stubDirectory{}}
	for _, q := range []string{"?limit=0", "?limit=-5", "?limit=lots"} {
		req := httptest.NewRequest(http.MethodGet, "/api/directory/recipients"+q, nil)
		rec := httptest.NewRecorder()
		s.handleDirectoryRecipients(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit %q returned %d, want 400", q, rec.Code)
		}
	}
}

// TestImportNeverIncludesDisabledAccounts guards the property at the API layer
// too, not just in the conversion, because this is the one that would be a
// disclosure rather than a nuisance.
func TestImportNeverIncludesDisabledAccounts(t *testing.T) {
	s := &Server{directory: &stubDirectory{users: []datasource.User{
		{Username: "a", Email: "a@example.com", IsActive: false},
		{Username: "b", Email: "b@example.com", IsActive: false},
	}}}
	_, body := getDirectoryRecipients(t, s, "")
	recipients, _ := body["recipients"].([]interface{})
	if len(recipients) != 0 {
		t.Errorf("disabled accounts reached the recipient list: %v", recipients)
	}
}
