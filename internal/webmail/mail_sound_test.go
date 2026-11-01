package webmail

import (
	"net/url"
	"strings"
	"testing"
)

func TestMailSoundIsSavedAndReachesThePage(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	save := func(sound string) {
		t.Helper()
		form := url.Values{"csrf": {csrf}, "mail_sound": {sound}, "week_start": {"0"}, "clock": {"24"}, "page_size": {"50"}}
		if resp := h.post("/settings", form); resp.StatusCode >= 400 {
			t.Fatalf("save %q: status %d", sound, resp.StatusCode)
		}
	}
	if _, page := h.get("/mail"); strings.Contains(page, "data-mail-sound") {
		t.Fatal("a sound is on by default")
	}
	save("marimba")
	if _, page := h.get("/mail"); !strings.Contains(page, `data-mail-sound="marimba"`) {
		t.Fatal("the page doesn't carry the choice")
	}
	if _, page := h.get("/settings"); !strings.Contains(page, `<option value="marimba" selected>`) {
		t.Fatal("settings don't show the choice")
	}
	// Whatever is posted, only a listed tone reaches the page.
	save(`"><script>`)
	if _, page := h.get("/mail"); strings.Contains(page, "data-mail-sound") {
		t.Fatal("an unlisted value was kept")
	}
}
