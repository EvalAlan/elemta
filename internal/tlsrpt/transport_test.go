package tlsrpt

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

type reportResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (fn reportResolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return fn(ctx, host)
}

type reportRoundTrip func(*http.Request) (*http.Response, error)

func (fn reportRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestReportDestinationRejectsPrivateAndReboundDNS(t *testing.T) {
	answers := []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}
	resolver := reportResolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return answers, nil })
	if _, err := reportDestinationIPs(context.Background(), resolver, "report.example"); err == nil {
		t.Fatal("accepted a destination with a private DNS answer")
	}
	answers = []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}
	if got, err := reportDestinationIPs(context.Background(), resolver, "report.example"); err != nil || len(got) != 1 {
		t.Fatalf("public report destination: %v %v", got, err)
	}
	answers = []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}
	if _, err := reportDestinationIPs(context.Background(), resolver, "report.example"); err == nil {
		t.Fatal("accepted rebound link-local destination")
	}
}

func TestReportPostDoesNotFollowRedirect(t *testing.T) {
	r, err := NewReporter(Config{From: "reports@example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	r.http.Transport = reportRoundTrip(func(req *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusTemporaryRedirect,
			Header: http.Header{"Location": {"http://127.0.0.1/private"}},
			Body:   io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	if err := r.post(context.Background(), "https://report.example/upload", []byte("report")); err == nil {
		t.Fatal("accepted redirected report")
	}
	if requests != 1 {
		t.Fatalf("followed redirect %d times", requests)
	}
}
