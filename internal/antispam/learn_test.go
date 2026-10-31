package antispam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLearnStatuses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantErr   bool
		wantFinal bool // ErrLearnRefused: the caller should stop retrying
	}{
		{"learned", http.StatusOK, false, false},
		{"already learned", http.StatusAlreadyReported, false, false},
		{"too short to tokenise", http.StatusNoContent, false, false},
		{"bad message", http.StatusBadRequest, true, true},
		{"wrong password is retried once fixed", http.StatusUnauthorized, true, false},
		{"rspamd failing is retried", http.StatusInternalServerError, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()
			err := NewLearner(srv.URL, "pw").Learn(context.Background(), LearnSpam, []byte("message"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if errors.Is(err, ErrLearnRefused) != tt.wantFinal {
				t.Fatalf("err = %v, want refused %v", err, tt.wantFinal)
			}
		})
	}
}

func TestLearnRequest(t *testing.T) {
	var path, password, body string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		path, password = r.URL.Path, r.Header.Get("Password")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()

	l := NewLearner(srv.URL+"/", "secret")
	if err := l.Learn(context.Background(), LearnHam, []byte("message")); err != nil {
		t.Fatal(err)
	}
	if path != "/learnham" || password != "secret" || body != "message" {
		t.Fatalf("path %q password %q body %q", path, password, body)
	}
	if err := l.Learn(context.Background(), LearnSpam, []byte("message")); err != nil {
		t.Fatal(err)
	}
	if path != "/learnspam" {
		t.Fatalf("path %q", path)
	}
	if err := l.Learn(context.Background(), "other", []byte("message")); err == nil {
		t.Fatal("an unknown class must not be sent")
	}
}

func TestLearnUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	err := NewLearner(srv.URL, "pw").Learn(context.Background(), LearnSpam, []byte("message"))
	if err == nil || errors.Is(err, ErrLearnRefused) {
		t.Fatalf("an unreachable Rspamd must be retried, got %v", err)
	}
}
