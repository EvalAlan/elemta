# Elemta Test Suite

Tests for the Elemta MTA, organized around a single integration interface plus
Go unit/integration tests.

## Layout

| Path | What it is | How to run |
|------|-----------|-----------|
| `internal/**/*_test.go` | Go unit tests (live next to the code they cover) | `make test` or `go test ./...` |
| `tests/*.go`, `tests/integration/` | Go integration tests (SMTP protocol / RFC 5321 / flow) | `go test ./tests/...` |
| `tests/test_elemta_centralized.py` | **Centralized integration suite** — the single interface for deployment, SMTP, auth, security, performance, e2e and monitoring checks | `./tests/run_centralized_tests.sh` |
| `tests/performance/` | Load / stress tests | `make test-load` |
| `tests/*.py`, `tests/*.sh` (specialized) | Standalone checks for subsystems the centralized suite does not yet cover (see below) | run individually |
| `tests/{config,corpus,data,fixtures,docker,k8s,scripts}` | Test assets, fixtures and helpers | — |

Test *plans* and security-review documents (design docs, not executable) live in
[`docs/test-plans/`](../docs/test-plans/).

## Quick start

```bash
# Go unit tests (fast, no services required)
make test

# Full centralized integration suite (requires the Docker stack up)
make test-docker            # == ./tests/run_centralized_tests.sh --deployment docker-dev

# A single category, e.g. security
make test-security          # == ./tests/run_centralized_tests.sh --category security

# Go integration tests
go test ./tests/...

# Load tests
make test-load
```

The centralized runner supports category and single-test selection:

```bash
./tests/run_centralized_tests.sh --category smtp --category auth
./tests/run_centralized_tests.sh --test smtp-greeting
./tests/run_centralized_tests.sh --help
```

Registered categories: `deployment`, `smtp`, `auth`, `security`, `performance`,
`e2e`, `monitoring`.

## Specialized standalone scripts

These predate the centralized suite and cover subsystems it does not yet
exercise. They run against a live stack and are invoked directly (stdlib Python /
bash, no extra deps). New coverage should preferably be added to
`test_elemta_centralized.py` rather than as new standalone scripts; these remain
until their coverage is migrated.

| Script | Covers |
|--------|--------|
| `test_lmtp_direct.py` | LMTP delivery to Dovecot |
| `test_managesieve_integration.py` | ManageSieve auth + Sieve script management |
| `test-multinode-valkey.py` | Distributed rate limiting across nodes via Valkey |
| `test_email_logging.py` | Email transaction logging |
| `test_email_content_validation.py` | Email content validation/sanitization (ELE-18) |
| `test_smtp_command_security.py` | SMTP command parsing / buffer-overflow handling (ELE-33) |
| `test_relay_control.py` | Internal vs external relay rules |
| `test_auth_chain.sh` | Authentication chain |
| `swaks_load_test.sh`, `run_swaks_corpus.sh` | swaks-based load / corpus runs |

## Environment

Defaults target the Docker dev stack:

- SMTP: `localhost:2525`
- LDAP: `localhost:389`
- Roundcube: `http://localhost:8025`
- ManageSieve: `localhost:4190`

Bring the stack up with `docker-compose up -d` (or `make up`) and wait for
services to become healthy before running integration/e2e tests.

## Adding tests

- **Unit tests:** add `*_test.go` next to the code under `internal/`.
- **Integration/e2e:** register a new `TestCase` in `test_elemta_centralized.py`
  under the appropriate category.
- **Load/perf:** add to `tests/performance/`.
