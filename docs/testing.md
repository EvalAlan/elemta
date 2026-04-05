# Elemta Testing Guide

This is the current, supported testing flow for Elemta.

## Test layers

1. **Fast unit/lint checks** (default PR baseline)
2. **Queue/backend guardrails** (sqlite + race-sensitive queue paths)
3. **Integration/load checks** (docker + SMTP flow/load)
4. **Targeted race checks** (SMTP/session lifecycle smoke)

## Local command reference

## Baseline checks

```bash
make test
make lint
```

Equivalent direct commands:

```bash
go test ./...
go vet ./...
golangci-lint run ./cmd/... ./internal/... --timeout=10m
```

## Queue backend checks

```bash
go test ./internal/queue/... -race
go test ./internal/queue/... -run '^TestQueueSQLiteGuardrails_'
```

## SMTP race smoke checks

```bash
go test ./internal/smtp -race -run 'TestHandleUnknown|TestCommandSequencing|TestConnectionDraining'
go test ./tests/integration -race -run 'TestIntegration_PersistentConnection|TestIntegration_TimeoutHandling'
```

## Docker/dev stack checks

```bash
make install-dev
make test-load
```

Optional full stack:

```bash
make install-dev-full
```

## CI expectations

Current CI gates include short/full tests plus queue race/guardrail jobs. For concurrency-sensitive changes in SMTP/session internals, run SMTP race smoke checks locally before opening a PR.

## When to run what

- **Small refactor/docs only:** `make test` + `make lint`
- **Queue/backend changes:** baseline + queue checks
- **SMTP/session/concurrency changes:** baseline + SMTP race smoke checks
- **Deployment/runtime changes:** baseline + docker/load checks

## Failure triage tips

1. Re-run the exact failing command first (avoid broad reruns).
2. If race failures appear, isolate with `-run` and keep logs.
3. For docker-dependent failures, inspect service health/logs:
   - `make status`
   - `make logs-elemta`
4. Update tests and docs in the same PR when behavior changes.
