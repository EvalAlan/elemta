package mailbox

import (
	"strings"
	"testing"
)

func TestQuotaLevel(t *testing.T) {
	th := []int{80, 95}
	for _, c := range []struct {
		used, limit int64
		want        int
	}{{0, 100, 0}, {79, 100, 0}, {80, 100, 80}, {94, 100, 80}, {95, 100, 95}, {120, 100, 95}, {50, 0, 0}} {
		if got := quotaLevel(th, c.used, c.limit); got != c.want {
			t.Errorf("quotaLevel(%d/%d) = %d, want %d", c.used, c.limit, got, c.want)
		}
	}
}

func TestQuotaWarnings(t *testing.T) {
	r := newAddressingRig(t)
	r.setAccount("ana", func(a *Account) { a.Quota = 100 << 10 })
	big := func(kb int) string { return msgWith("big") + strings.Repeat("x", kb<<10) + "\r\n" }
	warnings := func() (n int, subjects []string) {
		for _, m := range r.inbox("ana") {
			if strings.Contains(m, "Auto-Submitted: auto-generated") && strings.Contains(m, "Your mailbox is") {
				n++
				subjects = append(subjects, m[strings.Index(m, "Subject: "):][:30])
			}
		}
		return
	}
	r.send("x@example.org", "", []string{r.addr("ana")}, big(50))
	if n, _ := warnings(); n != 0 {
		t.Fatalf("warned at half full")
	}
	r.send("x@example.org", "", []string{r.addr("ana")}, big(32))
	if n, s := warnings(); n != 1 || !strings.Contains(s[0], "80%") {
		t.Fatalf("at 80%%: %d warnings %v", n, s)
	}
	r.send("x@example.org", "", []string{r.addr("ana")}, msgWith("small"))
	if n, _ := warnings(); n != 1 {
		t.Fatal("warned twice for the same threshold")
	}
	r.send("x@example.org", "", []string{r.addr("ana")}, big(12))
	if n, s := warnings(); n != 2 || !strings.Contains(strings.Join(s, " "), "95%") {
		t.Fatalf("at 95%%: %d warnings %v", n, s)
	}
}

func TestQuotaWarningAdministratorCopy(t *testing.T) {
	r := newAddressingRig(t)
	r.setAccount("ana", func(a *Account) { a.Quota = 100 << 10 })
	r.send("x@example.org", "", []string{r.addr("ana")}, msgWith("first")+strings.Repeat("x", 82<<10)+"\r\n")
	if got := r.inbox("ben"); len(got) != 0 {
		t.Fatalf("default configuration copied a warning: %d messages", len(got))
	}

	r.svc.cfg.Quota.CopyTo = r.addr("ben")
	r.send("x@example.org", "", []string{r.addr("ana")}, msgWith("second")+strings.Repeat("x", 14<<10)+"\r\n")
	copies := r.inbox("ben")
	if len(copies) != 1 || !strings.Contains(copies[0], "To: <"+r.addr("ben")+">") ||
		!strings.Contains(copies[0], "Mailbox "+r.addr("ana")+" is 95% full") ||
		!strings.Contains(copies[0], "Mailbox ("+r.addr("ana")+")") {
		t.Fatalf("administrator warning copy: %v", copies)
	}
}
