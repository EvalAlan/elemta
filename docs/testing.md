# Testing Guide

Current supported test flow for this repo.

---

## Fast baseline (default before PR)

```bash
make test
make lint
```

---

## Queue backend checks

```bash
go test ./internal/queue/... -race
go test ./internal/queue/... -run '^TestQueueSQLiteGuardrails_'
```

---

## SMTP/session race smoke checks

```bash
make test-race-smoke
```

Equivalent direct commands:

```bash
go test ./internal/smtp -race -run 'TestHandleUnknown|TestCommandSequencing|TestConnectionDraining'
go test ./tests/integration -race -run 'TestIntegration_PersistentConnection|TestIntegration_TimeoutHandling'
```

---

## Against a running stack

Load, stress and end-to-end checks against a running deployment live in the
separate elemta-tests repository. Bring a stack up with `make install-dev`
and point them at it.

Optional broader local stack:

```bash
make install-dev-full
```

---

## Suggested matrix

- **Docs/small refactor:** `make test` + `make lint`
- **Queue/backend changes:** baseline + queue backend checks
- **SMTP/session/concurrency:** baseline + race smoke checks
- **Runtime/deployment changes:** baseline + elemta-tests against `make install-dev`

---

## Failure triage

1. Re-run only the failing command first.
2. For docker-dependent failures:
   - `make status`
   - `make logs-elemta`
3. For race failures, keep `-race` + narrow `-run` filters.
4. Update docs/tests in the same PR when behavior changes.
