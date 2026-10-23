# Go integration tests

Elemta's tests are Go. Unit tests live next to the code they cover
(`internal/**/*_test.go`); this directory holds the protocol-level ones.

| Path | What | Run |
|---|---|---|
| `*_test.go` | SMTP behaviour against RFC 5321, server lifecycle, functional flows | `go test ./tests/` |
| `integration/` | Whole SMTP conversations (persistent connections, timeouts) | `go test ./tests/integration` |
| `scripts/*/` | Small Go programs that send a test message, an AUTH attempt, a spam sample or a virus sample to a running server | `go run ./tests/scripts/test-email` |

`make test` runs every Go test as CI does. Load, stress and end-to-end checks
against a running deployment are in the separate elemta-tests repository.
