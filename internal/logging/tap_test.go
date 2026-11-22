package logging

import (
	"strings"
	"testing"
)

func TestTapGetsStartUpAndWhatFollows(t *testing.T) {
	SetTap(func([]byte) {}) // let go of what other tests logged
	SetTap(nil)
	t.Cleanup(func() { SetTap(func([]byte) {}) })
	buf := []byte("at start\n")
	if _, err := tap.Write(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf, "REUSED!!") // slog reuses what it writes from
	var got []string
	SetTap(func(p []byte) { got = append(got, string(p)) })
	if _, err := tap.Write([]byte("later\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "") != "at start\nlater\n" {
		t.Fatalf("got %q", got)
	}
}
