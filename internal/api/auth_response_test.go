package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// An unauthenticated request gets one of two answers: a browser navigating to a
// page is redirected to the login form, everything else is told 401.
//
// The original test asked whether the request "looked like a browser" by
// treating `Accept: */*` as one, and an absent `X-Requested-With` as one too.
// Between them that is nearly every API client — curl, Go's http.Client, most
// HTTP libraries — so programmatic callers were answered with a 302 to an HTML
// login page instead of a status they could act on.

func TestWantsLoginPage(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		accept string
		want   bool
	}{
		{
			name:   "browser navigating to the dashboard",
			method: http.MethodGet, path: "/",
			accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			want:   true,
		},
		{
			name:   "curl hitting an API endpoint",
			method: http.MethodGet, path: "/api/queue/stats",
			accept: "*/*",
			want:   false,
		},
		{
			name:   "API client sending no Accept at all",
			method: http.MethodGet, path: "/api/config",
			accept: "",
			want:   false,
		},
		{
			name:   "API endpoint is never a login redirect, even asking for HTML",
			method: http.MethodGet, path: "/api/queue/active",
			accept: "text/html",
			want:   false,
		},
		{
			name:   "JSON client on a non-API path",
			method: http.MethodGet, path: "/dashboard",
			accept: "application/json",
			want:   false,
		},
		{
			name:   "a POST is never redirected",
			method: http.MethodPost, path: "/dashboard",
			accept: "text/html",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}
			if got := wantsLoginPage(r); got != tc.want {
				t.Errorf("wantsLoginPage(%s %s, Accept:%q) = %v, want %v",
					tc.method, tc.path, tc.accept, got, tc.want)
			}
		})
	}
}
