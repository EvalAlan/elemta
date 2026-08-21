// Command arctool drives Elemta's ARC implementation from the shell so it can
// be checked against an independent one.
//
// It exists for scripts/dev/arc_crossvalidate.py. Testing a signer against its
// own verifier proves only that the two agree; a canonicalization mistake made
// consistently in both directions passes every such test. Pairing this tool
// with dkimpy catches exactly that class of bug.
//
// Development tooling. Nothing in the server depends on it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/EvalAlan/elemta/internal/arc"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: arctool <seal|verify> [flags] < message")
	}

	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	zoneJSON := flags.String("zone", "", "JSON object mapping TXT record names to record strings")
	keyPath := flags.String("key", "", "PEM private key (seal only)")
	domain := flags.String("domain", "", "sealing domain (seal only)")
	selector := flags.String("selector", "", "sealing selector (seal only)")
	authResults := flags.String("ar", "", "Authentication-Results value to record (seal only)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail("%v", err)
	}

	message, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("reading message: %v", err)
	}

	resolver, err := zoneResolver(*zoneJSON)
	if err != nil {
		fail("%v", err)
	}

	switch command {
	case "seal":
		plugin, err := arc.New(arc.Config{
			Enabled: true, Verify: true, Seal: true,
			Domain: *domain, Selector: *selector, PrivateKeyPath: *keyPath,
			HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed",
			Timeout: 10 * time.Second,
		})
		if err != nil {
			fail("configuring sealer: %v", err)
		}
		plugin.SetResolver(resolver)
		sealed, err := plugin.Seal(context.Background(), message, *authResults)
		if err != nil {
			fail("sealing: %v", err)
		}
		if _, err := os.Stdout.Write(sealed); err != nil {
			fail("writing: %v", err)
		}

	case "verify":
		plugin, err := arc.New(arc.Config{Enabled: true, Verify: true, Timeout: 10 * time.Second})
		if err != nil {
			fail("configuring verifier: %v", err)
		}
		plugin.SetResolver(resolver)
		result := plugin.Verify(context.Background(), message)
		fmt.Printf("%s\t%s\n", result.Value, result.Reason)
		if result.Value != "pass" {
			os.Exit(1)
		}

	default:
		fail("unknown command %q", command)
	}
}

// zoneResolver serves TXT records from an inline JSON object so the check never
// touches the network.
//
// The zone arrives as an argument rather than a file path deliberately: a tool
// that opens a caller-supplied path is a path-traversal finding that would have
// to be argued away, and there is nothing here that needs a file.
func zoneResolver(inline string) (arc.TXTResolver, error) {
	if inline == "" {
		return nil, nil
	}
	var zone map[string][]string
	if err := json.Unmarshal([]byte(inline), &zone); err != nil {
		return nil, fmt.Errorf("parsing zone: %w", err)
	}
	return func(_ context.Context, name string) ([]string, error) {
		records, ok := zone[name]
		if !ok {
			return nil, fmt.Errorf("no TXT record for %s", name)
		}
		return records, nil
	}, nil
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
