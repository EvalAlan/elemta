package valkeyaddr

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestDialGivesUpAfterWait(t *testing.T) {
	// A port nothing listens on: every attempt is refused.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	start := time.Now()
	if _, err := Dial(addr, nil, 1500*time.Millisecond); err == nil {
		t.Fatal("Dial to a closed port succeeded")
	}
	if took := time.Since(start); took < 700*time.Millisecond || took > 4*time.Second {
		t.Errorf("Dial gave up after %v, want about the 1.5s wait", took)
	}
	if _, err := Dial("valkey://:x@host:bad port", nil, time.Minute); err == nil {
		t.Error("Dial accepted an unparsable address")
	}
}
