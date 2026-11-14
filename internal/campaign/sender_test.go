package campaign

import "testing"

func TestSenderAllowed(t *testing.T) {
	hosted := []string{"example.com", "Example.org"}
	for _, tc := range []struct {
		from    string
		allowed []string
		want    bool
	}{
		{"news@example.com", nil, true},
		{"News <NEWS@EXAMPLE.ORG>", nil, true},
		{"ceo@bank.example", nil, false},
		{"news@sub.example.com", nil, false},
		{"not an address", nil, false},
		{"news@brand.example", []string{"brand.example"}, true},
		{"news@brand.example", []string{"@brand.example"}, true},
		{"other@example.com", []string{"news@example.com"}, false},
		{"news@example.com", []string{"news@example.com"}, true},
		{"ceo@bank.example", []string{"brand.example"}, false},
	} {
		if got := SenderAllowed(tc.from, hosted, tc.allowed); got != tc.want {
			t.Errorf("SenderAllowed(%q, %v) = %v, want %v", tc.from, tc.allowed, got, tc.want)
		}
	}
	for entry, want := range map[string]bool{
		"news@example.com": true, "example.com": true, "@example.com": true,
		"": false, "example": false, "a b.com": false, "News <n@example.com>": false,
	} {
		if got := ValidSenderEntry(entry); got != want {
			t.Errorf("ValidSenderEntry(%q) = %v, want %v", entry, got, want)
		}
	}
}
