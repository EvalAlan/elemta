package webmail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This opt-in test authenticates against the running Compose Dovecot and
// exercises DAV through the same SQL wrapper used by browser sessions.
func TestPostgresObjectsIMAP(t *testing.T) {
	if os.Getenv("ELEMTA_TEST_OBJECT_IMAP") != "1" {
		t.Skip("set ELEMTA_TEST_OBJECT_IMAP=1 for the running development stack")
	}
	dsn := os.Getenv("ELEMTA_TEST_OBJECT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("ELEMTA_TEST_OBJECT_POSTGRES_DSN is required")
	}
	secure := false
	cfg := Config{IMAPAddr: "127.0.0.1:14143", IMAPTLS: TLSModeNone, SubmissionAddr: "127.0.0.1:2587", SecureCookies: &secure, ObjectStore: "postgres", ObjectPostgresDSN: dsn}
	srv, err := NewServer(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const user = "stressuser20@example.com"
	defer func() {
		_, _ = srv.objectDB.Exec(`DELETE FROM webmail_objects WHERE mailbox=$1`, user)
		_, _ = srv.objectDB.Exec(`DELETE FROM webmail_object_users WHERE mailbox=$1`, user)
	}()
	st, err := srv.dial(ctx, user, "testpass123")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	uid := fmt.Sprintf("sql-live-%d", time.Now().UnixNano())
	card := "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:" + uid + "\r\nFN:SQL live test\r\nEND:VCARD\r\n"
	if err := st.PutObject(ctx, CollContacts, Object{ID: uid, Name: uid + ".vcf", ContentType: "text/vcard", Data: []byte(card)}); err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	request := func(method, body string) string {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, httpServer.URL+davAddressBook+uid+".vcf", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(user, "testpass123")
		req.Header.Set("Content-Type", "text/vcard")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Fatalf("DAV %s: %d %s", method, resp.StatusCode, data)
		}
		return string(data)
	}
	if data := request("GET", ""); !strings.Contains(data, "SQL live test") {
		t.Fatalf("DAV did not see webmail write: %s", data)
	}
	request("PUT", strings.ReplaceAll(card, "SQL live test", "DAV live edit"))
	objects, err := st.Objects(ctx, CollContacts)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, obj := range objects {
		if obj.ID == uid {
			found = strings.Contains(string(obj.Data), "DAV live edit")
		}
	}
	if !found {
		t.Fatal("webmail store did not see DAV edit")
	}
	if client := os.Getenv("ELEMTA_TEST_VDIRSYNCER"); client != "" {
		dir := t.TempDir()
		local := filepath.Join(dir, "cards", "default")
		if err := os.MkdirAll(local, 0700); err != nil {
			t.Fatal(err)
		}
		localCalendar := filepath.Join(dir, "calendars", "events")
		if err := os.MkdirAll(localCalendar, 0700); err != nil {
			t.Fatal(err)
		}
		calendar := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\nDTSTAMP:20261018T120000Z\r\nDTSTART:20261018T120000Z\r\nDTEND:20261018T130000Z\r\nSUMMARY:SQL calendar test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
		if err := st.PutObject(ctx, CollCalendar, Object{ID: uid, Name: uid + ".ics", ContentType: "text/calendar", Data: []byte(calendar)}); err != nil {
			t.Fatal(err)
		}
		config := fmt.Sprintf(`[general]
status_path = %q
[pair contacts]
a = "remote"
b = "local"
collections = ["default"]
[storage remote]
type = "carddav"
url = %q
username = %q
password = "testpass123"
[storage local]
type = "filesystem"
path = %q
fileext = ".vcf"
[pair events]
a = "calendar_remote"
b = "calendar_local"
collections = ["events"]
[storage calendar_remote]
type = "caldav"
url = %q
username = %q
password = "testpass123"
[storage calendar_local]
type = "filesystem"
path = %q
fileext = ".ics"
`, filepath.Join(dir, "status"), httpServer.URL+davContactsHome, user, filepath.Dir(local), httpServer.URL+davCalendarHome, user, filepath.Dir(localCalendar))
		configPath := filepath.Join(dir, "config")
		if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		run := func(command, pair string) {
			t.Helper()
			cmd := exec.CommandContext(ctx, client, "-c", configPath, command, pair)
			cmd.Stdin = strings.NewReader("y\n")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("vdirsyncer %s: %v\n%s", command, err, output)
			}
		}
		run("discover", "contacts")
		run("sync", "contacts")
		files, err := filepath.Glob(filepath.Join(local, "*.vcf"))
		if err != nil {
			t.Fatal(err)
		}
		var downloaded string
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), uid) {
				downloaded = file
				break
			}
		}
		if downloaded == "" {
			t.Fatal("real client did not download SQL-backed contact")
		}
		if err := os.WriteFile(downloaded, []byte(strings.ReplaceAll(card, "SQL live test", "Client live edit")), 0600); err != nil {
			t.Fatal(err)
		}
		run("sync", "contacts")
		if data := request("GET", ""); !strings.Contains(data, "Client live edit") {
			t.Fatalf("real client edit did not reach server: %s", data)
		}
		run("discover", "events")
		run("sync", "events")
		files, err = filepath.Glob(filepath.Join(localCalendar, "*.ics"))
		if err != nil {
			t.Fatal(err)
		}
		downloaded = ""
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), uid) {
				downloaded = file
				break
			}
		}
		if downloaded == "" {
			t.Fatal("real client did not download SQL-backed event")
		}
		if err := os.WriteFile(downloaded, []byte(strings.ReplaceAll(calendar, "SQL calendar test", "Client calendar edit")), 0600); err != nil {
			t.Fatal(err)
		}
		run("sync", "events")
		objects, err = st.Objects(ctx, CollCalendar)
		if err != nil {
			t.Fatal(err)
		}
		found = false
		for _, obj := range objects {
			if obj.ID == uid {
				found = strings.Contains(string(obj.Data), "Client calendar edit")
			}
		}
		if !found {
			t.Fatal("real client calendar edit did not reach SQL")
		}
	}
	request("DELETE", "")
}

type failingObjectSource struct{ ObjectStore }

func (f failingObjectSource) Objects(ctx context.Context, c Collection) ([]Object, error) {
	if c == CollContacts {
		return nil, errors.New("source unavailable")
	}
	return f.ObjectStore.Objects(ctx, c)
}

func TestPostgresObjects(t *testing.T) {
	dsn := os.Getenv("ELEMTA_TEST_OBJECT_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set ELEMTA_TEST_OBJECT_POSTGRES_DSN to a disposable Postgres database")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := initObjectSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	user := fmt.Sprintf("object-test-%d@example.com", time.Now().UnixNano())
	other := user + ".other"
	defer func() {
		_, _ = db.Exec(`DELETE FROM webmail_objects WHERE mailbox IN ($1,$2)`, user, other)
		_, _ = db.Exec(`DELETE FROM webmail_object_users WHERE mailbox IN ($1,$2)`, user, other)
	}()
	source := newFakeStore()
	stamp := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, c := range collections {
		if err := source.PutObject(ctx, c, Object{ID: "same-id", Name: "client-name", Title: string(c), Data: []byte("original"), Modified: stamp}); err != nil {
			t.Fatal(err)
		}
	}
	s := postgresObjects{db: db, user: user}
	if err := s.migrate(ctx, failingObjectSource{source}); err == nil {
		t.Fatal("migration succeeded with a broken source")
	}
	objects, err := s.Objects(ctx, CollCalendar)
	if err != nil || len(objects) != 0 {
		t.Fatalf("partial migration survived rollback: %v %v", objects, err)
	}
	// Two replicas attempting the first login must agree on one snapshot.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.migrate(ctx, source) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range collections {
		objects, err := s.Objects(ctx, c)
		if err != nil || len(objects) != 1 || !objects[0].Modified.Equal(stamp) {
			t.Fatalf("migration %s: %v %v", c, objects, err)
		}
	}
	if err := s.PutObject(ctx, CollCalendar, Object{ID: "same-id", Data: []byte{0, 255, 1}}); err != nil {
		t.Fatal(err)
	}
	objects, err = s.Objects(ctx, CollCalendar)
	if err != nil || len(objects) != 1 || objects[0].Name != "client-name" || string(objects[0].Data) != string([]byte{0, 255, 1}) || !objects[0].Modified.After(stamp) {
		t.Fatalf("update: %v %v", objects, err)
	}
	if err := s.PutObject(ctx, CollCalendar, Object{ID: "different-id", Name: "client-name"}); err == nil {
		t.Fatal("duplicate resource name accepted")
	}
	isolated := postgresObjects{db: db, user: other}
	if err := isolated.migrate(ctx, newFakeStore()); err != nil {
		t.Fatal(err)
	}
	if err := isolated.DeleteObject(ctx, CollCalendar, "same-id"); err != nil {
		t.Fatal(err)
	}
	objects, err = isolated.Objects(ctx, CollCalendar)
	if err != nil || len(objects) != 0 {
		t.Fatalf("mailbox isolation: %v %v", objects, err)
	}
	if err := s.DeleteObject(ctx, CollCalendar, "same-id"); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx, failingObjectSource{source}); err != nil {
		t.Fatalf("completed migration reread source: %v", err)
	}
	objects, err = s.Objects(ctx, CollCalendar)
	if err != nil || len(objects) != 0 {
		t.Fatalf("deleted item resurrected: %v %v", objects, err)
	}
	originals, err := source.Objects(ctx, CollCalendar)
	if err != nil || len(originals) != 1 {
		t.Fatal("migration changed the source")
	}
	if err := s.PutObject(ctx, Collection("unknown"), Object{ID: "bad"}); err == nil {
		t.Fatal("unknown collection accepted")
	}
}
