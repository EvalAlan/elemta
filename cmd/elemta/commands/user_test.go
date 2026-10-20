package commands

import (
	"reflect"
	"testing"
)

func TestUserRolesFor(t *testing.T) {
	t.Cleanup(func() { userDomains = nil })
	userDomains = []string{"example.com", "Other.Example"}
	got, err := rolesFor("domain-admin")
	if err != nil || !reflect.DeepEqual(got, []string{"domain-admin", "domain:example.com", "domain:other.example"}) {
		t.Fatalf("domain-admin = %v, %v", got, err)
	}
	if _, err := rolesFor("operator"); err == nil {
		t.Error("--domains accepted for a role that doesn't use them")
	}
	userDomains = nil
	if _, err := rolesFor("domain-admin"); err == nil {
		t.Error("a domain-admin without domains was accepted")
	}
	if got, err := rolesFor("readonly"); err != nil || !reflect.DeepEqual(got, []string{"readonly"}) {
		t.Errorf("readonly = %v, %v", got, err)
	}
	if _, err := rolesFor("root"); err == nil {
		t.Error("unknown role accepted")
	}
}
