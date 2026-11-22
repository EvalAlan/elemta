package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/suppression"
	"github.com/gorilla/mux"
)

func TestOneClickUnsubscribe(t *testing.T) {
	unsubscribeOnce, unsubscribeKey = sync.Once{}, nil
	dir := t.TempDir()
	store, err := suppression.Open(filepath.Join(dir, "suppressed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := &Server{configPath: filepath.Join(dir, "elemta.toml"), mainConfig: &MainConfig{Hostname: "mail.example.com"}, suppressed: store}
	r := mux.NewRouter()
	r.HandleFunc("/unsubscribe/{token}", s.handleUnsubscribe).Methods("GET", "POST")

	link := s.unsubscriber().URL("c7", "pat@example.com")
	if !strings.HasPrefix(link, "https://mail.example.com/unsubscribe/") {
		t.Fatalf("link %q", link)
	}
	path := strings.TrimPrefix(link, "https://mail.example.com")
	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("List-Unsubscribe=One-Click"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	suppressed := func() bool {
		_, ok, err := store.IsSuppressed(context.Background(), "pat@example.com")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// A link checker's GET changes nothing; it gets a button.
	if w := do("GET", path); w.Code != 200 || !strings.Contains(w.Body.String(), `<form method="post">`) || suppressed() {
		t.Fatalf("GET: %d suppressed=%v\n%s", w.Code, suppressed(), w.Body)
	}
	// The provider's one-click POST unsubscribes.
	if w := do("POST", path); w.Code != 200 || !strings.Contains(w.Body.String(), "unsubscribed") || !suppressed() {
		t.Fatalf("POST: %d suppressed=%v\n%s", w.Code, suppressed(), w.Body)
	}
	e, _, _ := store.IsSuppressed(context.Background(), "pat@example.com")
	if e.Source != suppression.SourceUnsubscribe || !strings.Contains(e.Reason, "c7") {
		t.Errorf("entry %+v", e)
	}
	// Twice is fine.
	if w := do("POST", path); w.Code != 200 {
		t.Errorf("second POST: %d", w.Code)
	}
	// A forged token unsubscribes nobody.
	if w := do("POST", "/unsubscribe/"+"cGF0QGV4YW1wbGUuY29t.AAAAAAAAAAAAAAAAAAAAAA"); w.Code != http.StatusNotFound {
		t.Errorf("forged token: %d", w.Code)
	}

	// The key survives a restart, so links in mail already sent keep working.
	unsubscribeOnce, unsubscribeKey = sync.Once{}, nil
	if _, _, ok := s.unsubscriber().Parse(strings.TrimPrefix(path, "/unsubscribe/")); !ok {
		t.Error("link stopped working after the key was reloaded")
	}
}
