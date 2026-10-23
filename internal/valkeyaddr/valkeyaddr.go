// Package valkeyaddr turns the Valkey address a service is configured with
// into client options, so every service accepts the same forms.
//
// A plain "host:port" is one Valkey server, which is what a single-host
// deployment runs. A URL is handed to valkey-go's parser, which is how a
// deployment that fails Valkey over names its Sentinels:
//
//	valkey://valkey-sentinel:26379?master_set=elemta
//	valkey://:password@s1:26379?addr=s2:26379&addr=s3:26379&master_set=elemta
//
// With master_set the client asks the Sentinels for the current primary and
// follows it when they promote a replica, so a Valkey pod being lost no longer
// costs every service its sessions, locks and shared counters until it is
// rescheduled.
package valkeyaddr

import (
	"fmt"
	"strings"

	"github.com/valkey-io/valkey-go"
)

// Options returns client options for addr. Callers set timeouts and caching
// on the result as before.
func Options(addr string) (valkey.ClientOption, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return valkey.ClientOption{}, fmt.Errorf("valkey: no address")
	}
	if !strings.Contains(addr, "://") {
		return valkey.ClientOption{InitAddress: []string{addr}}, nil
	}
	opt, err := valkey.ParseURL(addr)
	if err != nil {
		// The URL can carry a password, so name the problem, not the input.
		return valkey.ClientOption{}, fmt.Errorf("valkey: invalid address URL: %w", redact(err, addr))
	}
	// The password in the URL is the primary's. The Sentinels are left
	// without one: sending AUTH to a Sentinel that has none configured fails
	// the connection, and ours are reachable only from the namespace.
	return opt, nil
}

// NewClient connects with Options(addr); tune lets a caller adjust the
// options (timeouts, client-side caching) before the client is made.
func NewClient(addr string, tune func(*valkey.ClientOption)) (valkey.Client, error) {
	opt, err := Options(addr)
	if err != nil {
		return nil, err
	}
	if tune != nil {
		tune(&opt)
	}
	return valkey.NewClient(opt)
}

// Display is addr with any password removed, for logs and error messages.
func Display(addr string) string {
	at := strings.LastIndex(addr, "@")
	scheme := strings.Index(addr, "://")
	if at < 0 || scheme < 0 || at < scheme {
		return addr
	}
	return addr[:scheme+3] + "***" + addr[at:]
}

func redact(err error, addr string) error {
	if shown := Display(addr); shown != addr {
		return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), addr, shown))
	}
	return err
}
