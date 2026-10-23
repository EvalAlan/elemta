package valkeyaddr

import (
	"reflect"
	"strings"
	"testing"
)

func TestOptions(t *testing.T) {
	opt, err := Options("elemta-valkey:6379")
	if err != nil || !reflect.DeepEqual(opt.InitAddress, []string{"elemta-valkey:6379"}) || opt.Sentinel.MasterSet != "" {
		t.Fatalf("plain address: %+v, %v", opt.InitAddress, err)
	}

	opt, err = Options("valkey://:secret@s1:26379?addr=s2:26379&addr=s3:26379&master_set=elemta")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"s1:26379", "s2:26379", "s3:26379"}; !reflect.DeepEqual(opt.InitAddress, want) {
		t.Errorf("sentinels = %v, want %v", opt.InitAddress, want)
	}
	if opt.Sentinel.MasterSet != "elemta" || opt.Password != "secret" || opt.Sentinel.Password != "" {
		t.Errorf("sentinel options = %+v, password %q", opt.Sentinel, opt.Password)
	}

	if _, err := Options(""); err == nil {
		t.Error("empty address accepted")
	}
	_, err = Options("valkey://:secret@host:bad port")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("bad URL error = %v, want one without the password", err)
	}
}

func TestDisplay(t *testing.T) {
	for in, want := range map[string]string{
		"elemta-valkey:6379":                          "elemta-valkey:6379",
		"valkey://:pw@s1:26379?master_set=elemta":     "valkey://***@s1:26379?master_set=elemta",
		"valkey://s1:26379?addr=s2&master_set=elemta": "valkey://s1:26379?addr=s2&master_set=elemta",
	} {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
}
