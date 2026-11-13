package smtp

import (
	"testing"

	"github.com/EvalAlan/elemta/internal/authresult"
)

func dmarcResults(value, domain, policy, disposition string) authresult.Results {
	return authresult.Results{
		DMARC:       authresult.Result{Method: "dmarc", Value: value, Domain: domain},
		Policy:      policy,
		Disposition: disposition,
	}
}

// Mail failing DMARC for one of the server's own domains is refused when
// that domain publishes p=reject, even with DMARC enforcement off.
func TestOwnDomainDMARCRefusal(t *testing.T) {
	local := []string{"example.com", "Other.example."}
	cases := []struct {
		name    string
		results authresult.Results
		relay   bool
		refused bool
	}{
		{"forged own domain, p=reject", dmarcResults("fail", "example.com", "reject", "accept"), false, true},
		{"case and trailing dot", dmarcResults("fail", "OTHER.example", "reject", "accept"), false, true},
		{"own domain passes", dmarcResults("pass", "example.com", "reject", "accept"), false, false},
		{"own domain p=quarantine", dmarcResults("fail", "example.com", "quarantine", "accept"), false, false},
		{"own domain p=none", dmarcResults("fail", "example.com", "none", "accept"), false, false},
		{"someone else's domain", dmarcResults("fail", "elsewhere.example", "reject", "accept"), false, false},
		{"own relay", dmarcResults("fail", "example.com", "reject", "accept"), true, false},
		{"already refused by enforcement", dmarcResults("fail", "example.com", "reject", "reject"), false, false},
		{"no DMARC verdict", dmarcResults("none", "example.com", "", "accept"), false, false},
	}
	for _, tc := range cases {
		if err := ownDomainDMARCRefusal(tc.results, local, tc.relay); (err != nil) != tc.refused {
			t.Errorf("%s: got %v, want refused=%v", tc.name, err, tc.refused)
		}
	}
}
