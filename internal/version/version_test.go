package version

import (
	"strings"
	"testing"
)

func TestCopyright(t *testing.T) {
	for last, want := range map[int]string{2024: "© 2025 Alan Denniston", 2025: "© 2025 Alan Denniston", 2027: "© 2025–2027 Alan Denniston"} {
		if got := copyright(last); got != want {
			t.Errorf("copyright(%d) = %q, want %q", last, got, want)
		}
	}
	if got := Copyright(); !strings.HasPrefix(got, "© 2025") || !strings.HasSuffix(got, "Alan Denniston") {
		t.Errorf("Copyright() = %q", got)
	}
}
