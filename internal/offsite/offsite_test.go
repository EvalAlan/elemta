package offsite

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func keys(objs []Object) string {
	var out []string
	for _, o := range objs {
		out = append(out, o.Key)
	}
	return strings.Join(out, " ")
}

// Two backups a day for 70 days: keep the newest of each of the last 3 days
// and of each of the last 2 ISO weeks.
func TestPrune(t *testing.T) {
	var objs []Object
	start := at("2026-08-31T03:00:00Z") // a Monday
	for d := 0; d < 70; d++ {
		for _, h := range []int{3, 15} {
			ts := start.AddDate(0, 0, d).Add(time.Duration(h-3) * time.Hour)
			objs = append(objs, Object{Key: ts.Format("0102-15"), Taken: ts})
		}
	}
	keep, drop := Prune(objs, 3, 2)
	// The last day is 2026-11-08 (a Sunday, ending ISO week 45); week 44
	// ended on Sunday 2026-11-01.
	if got, want := keys(keep), "1108-15 1107-15 1106-15 1101-15"; got != want {
		t.Errorf("kept %q, want %q", got, want)
	}
	if len(keep)+len(drop) != len(objs) {
		t.Errorf("kept %d and dropped %d of %d", len(keep), len(drop), len(objs))
	}
}

func TestPruneNeverEmpties(t *testing.T) {
	one := []Object{{Key: "a", Taken: at("2026-11-06T03:00:00Z")}}
	if keep, drop := Prune(one, 0, 0); len(keep) != 1 || len(drop) != 0 {
		t.Fatalf("keep %v drop %v: the only backup must stay", keep, drop)
	}
	if keep, drop := Prune(nil, 14, 8); keep != nil || drop != nil {
		t.Fatalf("empty bucket: keep %v drop %v", keep, drop)
	}
}

func TestObjectName(t *testing.T) {
	c := &Client{cfg: Config{Prefix: "elemta/"}}
	if got, err := c.ObjectName("elemta-20261106T030000Z"); err != nil || got != "elemta/elemta-20261106T030000Z.tar.gz.age" {
		t.Errorf("ObjectName = %q, %v", got, err)
	}
	for _, bad := range []string{"elemta-today", "../elemta-20261106T030000Z", "other-20261106T030000Z"} {
		if _, err := c.ObjectName(bad); err == nil {
			t.Errorf("ObjectName(%q) accepted", bad)
		}
	}
}

// What Seal writes opens with the private key into the same directory, and
// nothing in it is readable without that key.
func TestSealRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "elemta-20261106T030000Z")
	files := map[string]string{
		"complete":            "",
		"manifest":            "created=2026-11-06T03:00:00Z\n",
		"ldap/data.ldif":      "dn: dc=example,dc=com\n",
		"mailbox/manifest":    "bodies=external\n",
		"secrets.tar.gz":      "KEY MATERIAL",
		"mta/elemta_config.x": strings.Repeat("config ", 1000),
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A socket, as a live volume's tar can meet, is left out.
	if l, err := net.Listen("unix", filepath.Join(dir, "rspamd.sock")); err == nil {
		defer func() { _ = l.Close() }()
	}

	var sealed bytes.Buffer
	if err := Seal(&sealed, dir, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Bytes(), []byte("KEY MATERIAL")) || bytes.Contains(sealed.Bytes(), []byte("dc=example")) {
		t.Fatal("the sealed backup isn't encrypted")
	}
	plain, err := age.Decrypt(&sealed, id)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(plain)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, _ := io.ReadAll(tr)
		got[h.Name] = string(b)
	}
	for name, body := range files {
		if got["elemta-20261106T030000Z/"+name] != body {
			t.Errorf("%s didn't come back as written", name)
		}
	}
	if len(got) != len(files) {
		t.Errorf("opened %d files, sealed %d: %v", len(got), len(files), got)
	}
}

func TestSealRefusesIncompleteBackups(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	if err := Seal(io.Discard, t.TempDir(), id.Recipient().String()); err == nil {
		t.Error("sealed a directory with no complete marker")
	}
	if err := Seal(io.Discard, t.TempDir(), "AGE-SECRET-KEY-1NOTAPUBLICKEY"); err == nil {
		t.Error("accepted something that isn't an age public key")
	}
}

func TestConfigFromEnv(t *testing.T) {
	for _, k := range []string{"BACKUP_S3_ENDPOINT", "BACKUP_S3_REGION", "BACKUP_S3_BUCKET", "BACKUP_S3_ACCESS_KEY_ID", "BACKUP_S3_SECRET_ACCESS_KEY", "BACKUP_S3_PREFIX"} {
		t.Setenv(k, "")
	}
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "BACKUP_S3_BUCKET") {
		t.Errorf("missing settings: %v", err)
	}
	t.Setenv("BACKUP_S3_ENDPOINT", "https://us-southeast-1.linodeobjects.com")
	t.Setenv("BACKUP_S3_BUCKET", "elemta-backup")
	t.Setenv("BACKUP_S3_ACCESS_KEY_ID", "id")
	t.Setenv("BACKUP_S3_SECRET_ACCESS_KEY", "secret")
	c, err := ConfigFromEnv()
	if err != nil || c.Endpoint != "us-southeast-1.linodeobjects.com" {
		t.Errorf("config = %+v, %v", c, err)
	}
}

// A symlink in the backup, to something outside it, never brings that file
// into the sealed archive: the walk is confined to the backup directory.
func TestSealLeavesOutLinksOutOfTheBackup(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	outside := filepath.Join(root, "shadow")
	if err := os.WriteFile(outside, []byte("OUTSIDE SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "elemta-20261106T030000Z")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "complete"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "manifest")); err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := Seal(&sealed, dir, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	plain, err := age.Decrypt(&sealed, id)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(plain)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(all, []byte("OUTSIDE SECRET")) {
		t.Fatal("a file outside the backup was sealed into it through a symlink")
	}
}
