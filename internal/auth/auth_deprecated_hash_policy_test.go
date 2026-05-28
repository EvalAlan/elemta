package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComparePasswordsSecureWithPolicy_DisablesDeprecatedSHA1(t *testing.T) {
	shaHash := "{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00=" // hello
	if err := comparePasswordsSecureWithPolicy(shaHash, "hello", false); err == nil {
		t.Fatal("expected SHA-1 auth to be blocked when deprecated hashes are disabled")
	}

	sshaHash := "{SSHA}qvTGHdzF6KLavt4PO0gs2a6pQ00="
	if err := comparePasswordsSecureWithPolicy(sshaHash, "hello", false); err == nil {
		t.Fatal("expected SSHA auth to be blocked when deprecated hashes are disabled")
	}
}

func TestComparePasswordsSecureWithPolicy_RejectsDeprecatedWhenEnabled(t *testing.T) {
	shaHash := "{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00=" // hello
	if err := comparePasswordsSecureWithPolicy(shaHash, "hello", true); err == nil {
		t.Fatalf("expected SHA-1 auth to be rejected even when legacy toggle is enabled")
	}

	sshaHash := "{SSHA}qvTGHdzF6KLavt4PO0gs2a6pQ00="
	if err := comparePasswordsSecureWithPolicy(sshaHash, "hello", true); err == nil {
		t.Fatalf("expected SSHA auth to be rejected even when legacy toggle is enabled")
	}
}

func TestNewWithFile_RespectsDeprecatedHashEnvToggle(t *testing.T) {
	t.Setenv("AUTH_ALLOW_DEPRECATED_SHA1", "false")

	tempDir := t.TempDir()
	usersPath := filepath.Join(tempDir, "users.txt")
	if err := os.WriteFile(usersPath, []byte("admin:password\n"), 0600); err != nil {
		t.Fatalf("failed writing users file: %v", err)
	}

	a, err := NewWithFile(usersPath)
	if err != nil {
		t.Fatalf("NewWithFile failed: %v", err)
	}
	defer func() { _ = a.Close() }()

	if a.allowDeprecatedSHA1 {
		t.Fatal("expected allowDeprecatedSHA1=false from env toggle")
	}
}
