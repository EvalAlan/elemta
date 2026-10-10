package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameOriginWrites(t *testing.T) {
	trusted := func(o string) bool { return o == "https://admin.example.net" }
	h := sameOriginWrites(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"read from anywhere", "GET", map[string]string{"Origin": "https://evil.example"}, 200},
		{"same-origin write", "POST", map[string]string{"Origin": "http://mail.example.com:8025"}, 200},
		{"same-origin write behind TLS proxy", "POST", map[string]string{"Origin": "https://mail.example.com:8025"}, 200},
		{"cross-origin write", "POST", map[string]string{"Origin": "https://evil.example"}, 403},
		{"cross-origin delete", "DELETE", map[string]string{"Origin": "https://evil.example"}, 403},
		{"cross-origin via referer only", "PUT", map[string]string{"Referer": "https://evil.example/page"}, 403},
		{"opaque origin", "POST", map[string]string{"Origin": "null"}, 403},
		{"trusted CORS origin", "POST", map[string]string{"Origin": "https://admin.example.net"}, 200},
		{"forwarded host", "POST", map[string]string{"Origin": "https://dash.example.org", "X-Forwarded-Host": "dash.example.org"}, 200},
		{"non-browser client", "POST", nil, 200},
		{"explicit credentials", "POST", map[string]string{"Origin": "https://evil.example", "Authorization": "Bearer key"}, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://mail.example.com:8025/api/config", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("got %d, want %d", rr.Code, tc.want)
			}
		})
	}
}
