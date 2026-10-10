package api

import (
	"net/http"
	"net/url"
	"strings"
)

// Cross-site request protection for the dashboard.
//
// The dashboard signs in with a cookie, and a browser attaches that cookie to
// a request any other site makes to this server. SameSite=Lax stops it on
// cross-site POSTs from most browsers, but not from same-site origins (another
// port or subdomain on the same registrable domain) and not from older
// browsers. An admin visiting the wrong page could otherwise flush queues,
// rewrite config or restart the server without knowing.
//
// Browsers send Origin on every cross-origin request that changes state, and
// Referer in most of the rest. So a state-changing request that names an
// origin other than this server's, and is not authenticated by a header a
// browser cannot attach on its own (Authorization: Basic or an API key), is
// refused. Requests with neither header come from non-browser clients, which
// have no ambient cookie to abuse, and are left alone.

// sameOriginWrites refuses cross-origin state-changing requests that rely on
// the session cookie. allowed reports origins explicitly trusted in the CORS
// configuration.
func sameOriginWrites(allowed func(origin string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) || r.Header.Get("Authorization") != "" {
				next.ServeHTTP(w, r)
				return
			}

			source := r.Header.Get("Origin")
			if source == "" || source == "null" {
				if ref := r.Header.Get("Referer"); ref != "" {
					source = ref
				} else if source == "" {
					next.ServeHTTP(w, r)
					return
				}
			}

			if requestIsSameOrigin(r, source) || (allowed != nil && allowed(originOf(source))) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Cross-origin request refused", http.StatusForbidden)
		})
	}
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// originOf reduces a URL to scheme://host[:port], the form Origin uses.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// requestIsSameOrigin reports whether source names the host this request was
// sent to. Behind a reverse proxy the browser's host arrives in
// X-Forwarded-Host, so that counts too. The scheme is not compared: TLS is
// often terminated in front of the server, so the request this server sees is
// plain HTTP while the browser's origin is https.
func requestIsSameOrigin(r *http.Request, source string) bool {
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Host)
	if strings.EqualFold(host, r.Host) {
		return true
	}
	for _, fwd := range strings.Split(r.Header.Get("X-Forwarded-Host"), ",") {
		if fwd = strings.TrimSpace(fwd); fwd != "" && strings.EqualFold(host, fwd) {
			return true
		}
	}
	return false
}
