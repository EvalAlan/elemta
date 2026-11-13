package delivery

import "testing"

// The policy host is named by the recipient's domain, so it may resolve
// anywhere; only public addresses are fetched from.
func TestPolicyHostMustBePublic(t *testing.T) {
	for addr, ok := range map[string]bool{
		"93.184.216.34:443":          true,
		"[2606:4700:4700::1111]:443": true,
		"127.0.0.1:443":              false,
		"10.253.53.7:443":            false,
		"169.254.169.254:443":        false,
		"100.64.0.1:443":             false,
		"[::1]:443":                  false,
		"[::ffff:10.0.0.1]:443":      false,
		"[fc00::1]:443":              false,
		"0.0.0.0:443":                false,
	} {
		if err := publicPolicyHost("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("publicPolicyHost(%s) = %v, want allowed=%v", addr, err, ok)
		}
	}
}
