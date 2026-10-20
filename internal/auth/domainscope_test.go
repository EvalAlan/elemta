package auth

import (
	"reflect"
	"testing"
)

func TestDomainScope(t *testing.T) {
	groups, err := DomainAdminGroups([]string{" Two.Example ", "one.example", "one.example", ""})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"domain-admin", "domain:one.example", "domain:two.example"}; !reflect.DeepEqual(groups, want) {
		t.Errorf("groups = %v, want %v", groups, want)
	}
	if got := DomainScope(append(groups, "user", "domain:ONE.example")); !reflect.DeepEqual(got, []string{"one.example", "two.example"}) {
		t.Errorf("scope = %v", got)
	}
	for _, bad := range [][]string{nil, {""}, {"localhost"}, {"a,b.example"}, {"x:y.example"}, {"-a.example"}} {
		if _, err := DomainAdminGroups(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
