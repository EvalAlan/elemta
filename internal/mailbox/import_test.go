package mailbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineImport(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	dir := t.TempDir()
	raw := "From: test@example.com\nSubject: imported\n\nbody\n.\n"
	if err := os.WriteFile(filepath.Join(dir, "message"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	date := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	folder := ImportFolder{Name: "INBOX", Validity: 1234567, Next: 19, Subscribed: true, Messages: []ImportMessage{
		{UID: 3, File: "message", Flags: []string{"\\Seen", "Label"}, Date: date},
		{UID: 17, File: "message", Flags: []string{"\\Flagged"}, Date: date},
	}}
	// A failed folder import must expose none of its partial metadata.
	folder.Messages[1].File = "missing"
	if err := e.ImportOfflineFolder(ctx, a.ID, folder, root); err == nil {
		t.Fatal("missing file accepted")
	}
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(messages) != 0 {
		t.Fatalf("partial publication: %v %v", messages, err)
	}
	folder.Messages[1].File = "message"
	for range 2 {
		if err := e.ImportOfflineFolder(ctx, a.ID, folder, root); err != nil {
			t.Fatal(err)
		}
	}
	f, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if f.Validity != folder.Validity || f.Next != 19 || len(messages) != 2 || messages[0].UID != 3 || messages[1].UID != 17 || !messages[0].Date.Equal(date) {
		t.Fatalf("identity changed: %+v %+v", f, messages)
	}
	body, err := e.Read(ctx, messages[0])
	if err != nil || string(body) != strings.ReplaceAll(raw, "\n", "\r\n") {
		t.Fatalf("body changed: %q %v", body, err)
	}
	folder.Name = "Contacts"
	if err := e.ImportOfflineFolder(ctx, a.ID, folder, root); err != nil {
		t.Fatal(err)
	}
	folder.Name = "INBOX"
	folder.Messages[0].Flags = nil
	if err := e.ImportOfflineFolder(ctx, a.ID, folder, root); err == nil {
		t.Fatal("different retry accepted")
	}
	result, err := e.Append(ctx, a.ID, "INBOX", []byte(raw), nil, time.Now(), "")
	if err != nil || result.UID != 19 || result.Validity != folder.Validity {
		t.Fatalf("next append: %+v %v", result, err)
	}
}

func TestImportSnapshotContainment(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := importBytes(root, ImportMessage{File: "../secret"}, 1024); err == nil {
		t.Fatal("escaped snapshot")
	}
	if err := os.WriteFile(filepath.Join(root.Name(), "message"), []byte("a\r\nb\nc\x00\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := importBytes(root, ImportMessage{File: "message"}, 100)
	if err != nil || string(raw) != "a\r\nb\r\nc\x00\r\n" {
		t.Fatalf("normalization: %q %v", raw, err)
	}
}
