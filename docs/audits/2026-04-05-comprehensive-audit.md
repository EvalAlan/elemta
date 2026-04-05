# Elemta Comprehensive Code Review & Security Audit

_Date:_ 2026-04-05  
_Scope:_ code quality, security posture, tests, docs hygiene, OSS readiness  
_Branch:_ `feat/comprehensive-audit-roadmap`

## Methodology

### Automated checks run

- `go test ./...`
- `go vet ./...`
- `golangci-lint run --timeout=10m ./cmd/... ./internal/... ./tests/...`
- `govulncheck ./...`
- `gosec -severity high ./...`
- targeted race checks:
  - `go test ./internal/smtp -race -run 'TestHandleUnknown|TestCommandSequencing|TestConnectionDraining'`
  - `go test ./tests/integration -race -run 'TestIntegration_PersistentConnection|TestIntegration_TimeoutHandling'`

### Baseline outcome summary

- Unit/lint/vet baseline: **pass**
- Security scanners: **action required**
- Full SMTP race sweep: **still has known race failures in memory manager tests**
- Docs/OSS hygiene: **major drift identified**

---

## Findings

## 1) Security findings

### High: Go stdlib vulnerabilities (reachable)

`govulncheck` reported reachable vulnerabilities in current toolchain:

- **GO-2026-4602** (`os@go1.25.7`, fixed in go1.25.8)
- **GO-2026-4601** (`net/url@go1.25.7`, fixed in go1.25.8)

Reachability examples included API server and rspamd HTTP paths.

**Risk:** reachable stdlib issues in network-facing software.  
**Remediation:** bump Go patch version in CI/build/runtime images and re-run vuln scan as release gate.

### Medium: Configurable TLS verification bypass

`internal/delivery/manager.go` allows `TLSInsecureSkipVerify` from config.

**Risk:** misconfiguration can silently weaken outbound TLS validation.  
**Remediation:** keep default false (already), add production profile guardrails + startup warning/error in strict mode.

### Medium: Legacy password hash compatibility modes

`internal/auth/auth.go` supports `{SHA}` and `{SSHA}` for compatibility and warns at runtime.

**Risk:** weak hash schemes may remain deployed indefinitely.  
**Remediation:** add policy switch to disable legacy hashes in production and provide migration tooling/reporting.

### Scanner noise (triage needed)

`gosec` reports include many signal/noise mixed items:

- `G115` conversion warnings (many likely low-risk but should be triaged)
- `G404` weak RNG usage in queue retry jitter
- `G702/G703` taint warnings (some likely false positives)

**Remediation:** create tracked triage list and suppress only with justification.

---

## 2) Reliability/concurrency findings

### High: race defects in SMTP server lifecycle (partially fixed in this pass)

Previously reproducible races around listener/running state under start/shutdown/readiness tests.

**Changes made in this pass:**

- synchronized listener access with lock helpers (`getListener` / `setListener`)
- moved `running` state to atomic bool
- hardened accept loop and queue-metrics loop shutdown behavior
- fixed shutdown test nil-listener panic path

Files changed:

- `internal/smtp/server.go`
- `internal/smtp/server_shutdown_test.go`

### High: race defects in worker pool stats (fixed in this pass)

Worker stats mixed atomic and non-atomic writes to the same fields.

**Changes made in this pass:**

- removed conflicting atomic writes to circuit-breaker sub-stats
- switched stats snapshot reads to atomic loads for atomic fields
- kept mutex-protected snapshot for structured circuit breaker state

File changed:

- `internal/smtp/worker_pool.go`

### Remaining reliability gap

`go test ./internal/smtp -race` still reports race failures in memory manager-focused tests (`TestMemoryManager*`, context propagation path). Those are still open and should be treated as Phase 0 blockers.

---

## 3) Test strategy findings

### Strengths

- broad unit/integration coverage across SMTP, queue, auth, API
- queue backend guardrails exist for sqlite path

### Gaps

- full race lane is not a required CI gate
- concurrency regressions can slip in outside queue package
- testing docs are stale and refer to scripts no longer canonical

**Remediation:** add race smoke lanes for critical SMTP/session paths and align testing docs to actual maintained commands.

---

## 4) Documentation and OSS readiness findings

### Broken/incorrect docs

- README had invalid image URL suffix and outdated run commands
- docs had broken links (including queue monitoring link and missing config examples)
- testing docs referenced legacy/non-canonical flows

### Missing OSS governance docs

Missing before this pass:

- `CONTRIBUTING.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `SUPPORT.md`
- project-level `ROADMAP.md`

### Stale/cruft candidates

- historical status/task docs no longer reflect current architecture/branching
- outdated config narrative (YAML references vs current TOML-first runtime)
- deadcode scan flags sizeable unreachable areas (especially legacy/example paths), needs curated cleanup plan

---

## Changes delivered in this audit pass

- Concurrency hardening and race-related fixes:
  - `internal/smtp/server.go`
  - `internal/smtp/worker_pool.go`
  - `internal/smtp/server_shutdown_test.go`
- OSS project hygiene docs added:
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
  - `SUPPORT.md`
  - `ROADMAP.md`
- README modernized to current commands/docs:
  - `README.md`

---

## Prioritized remediation plan

## P0 (immediate)

1. Upgrade Go patch version everywhere (local, CI, Docker image).
2. Close remaining SMTP race-test failures (`internal/smtp` memory manager suite).
3. Add CI race smoke lane for critical SMTP paths.
4. Triage gosec highs into true/false positives with explicit suppression comments where needed.

## P1 (near term)

1. Enforce safer TLS defaults/policies for outbound delivery.
2. Add legacy-auth-hash migration mode and strict-disable option.
3. Align/trim stale docs and remove dead links throughout docs tree.

## P2 (mid term)

1. Curate and remove/archive dead or obsolete code paths/docs/scripts.
2. Strengthen integration tests for queue backend transitions and fault recovery.
3. Expand operational runbooks and incident playbooks.

---

## Success criteria

- `govulncheck` clean for reachable vulns on release branch
- race smoke suite green in CI
- no critical/high unresolved security findings without documented risk acceptance
- docs reflect actual runtime behavior and supported workflows
- OSS governance docs complete and discoverable from README
