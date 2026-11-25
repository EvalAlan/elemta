package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// originating_ip is on the reception line only when the message had the
// header: a blank one would read as a header that was there and empty.
func TestReceptionOriginatingIP(t *testing.T) {
	for _, tc := range []struct {
		ip      string
		present bool
	}{{"203.0.113.9", true}, {"", false}} {
		var buf bytes.Buffer
		NewMessageLogger(slog.New(slog.NewJSONHandler(&buf, nil))).LogReception(MessageContext{MessageID: "<m@x>", OriginatingIP: tc.ip})
		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		got, present := line["originating_ip"]
		if present != tc.present || (present && got != tc.ip) {
			t.Errorf("OriginatingIP %q: logged %v (present %v)", tc.ip, got, present)
		}
	}
}

// dkim_signed is on the reception and delivery lines only when this server
// signed the message, so counting it counts signed mail and nothing else.
func TestDKIMSignedLogged(t *testing.T) {
	for _, tc := range []struct {
		domain  string
		present bool
	}{{"example.com", true}, {"", false}} {
		for name, log := range map[string]func(*MessageLogger, MessageContext){
			"reception": (*MessageLogger).LogReception,
			"delivery":  (*MessageLogger).LogDelivery,
		} {
			var buf bytes.Buffer
			log(NewMessageLogger(slog.New(slog.NewJSONHandler(&buf, nil))), MessageContext{MessageID: "<m@x>", DKIMSigned: tc.domain})
			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatal(err)
			}
			got, present := line["dkim_signed"]
			if present != tc.present || (present && got != tc.domain) {
				t.Errorf("%s, DKIMSigned %q: logged %v (present %v)", name, tc.domain, got, present)
			}
		}
	}
}
