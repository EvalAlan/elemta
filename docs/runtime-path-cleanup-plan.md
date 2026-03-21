# Runtime Path Cleanup Plan

## Why this exists

Elemta now has a real native packaging path on `main`:

- RPM/DEB packaging scaffolding
- `/etc/elemta`, `/var/lib/elemta`, `/var/spool/elemta`, `/var/log/elemta`, `/run/elemta`
- host install/start/stop/uninstall testing

That exposed an important reality:

**core runtime defaults still assume `/app/...` in too many places.**

That is acceptable for container-specific examples and Docker deployments, but it is no longer acceptable as the implicit default behavior for native/package installs.

This plan exists to separate:

- container-specific paths that should remain
- core runtime defaults that should be cleaned up
- documentation that needs clarification

---

## Goal

Make Elemta's runtime defaults and documentation consistent with a dual deployment model:

1. **Native/package installs** using standard Linux paths
2. **Container deployments** using `/app/...` paths where appropriate

The goal is **not** to delete all `/app/...` references.
The goal is to stop `/app/...` from leaking into places where it behaves like the universal default.

---

## Scope

### In scope

- runtime/code defaults that silently fall back to `/app/...`
- command-layer defaults that assume container layout
- logging/auth/config defaults that break native expectations
- documentation that incorrectly presents `/app/...` as the general/default path model

### Out of scope

- container-only docs that intentionally use `/app/...`
- Kubernetes/container examples where `/app/...` is correct
- broad config schema redesign
- packaging redesign

---

## Current Problem Areas

### 1. Code/runtime defaults

Observed likely cleanup targets:

- `internal/config/config.go`
- `cmd/elemta/commands/server.go`
- `cmd/elemta/commands/queue.go`
- `internal/logging/logging.go`
- `internal/auth/auth.go`
- `internal/api/server.go`

Why these matter:

- host/native runs should not silently drift to `/app/...`
- package/systemd execution should behave consistently with packaged config
- logging and queue behavior should not assume a container image layout

### 2. Tests encoding old assumptions

Examples:

- `internal/config/config_validation_test.go`
- other config/security tests that assume `/app/...` is the default canonical path

Need to distinguish:

- tests that validate container defaults intentionally
- tests that accidentally encode stale universal assumptions

### 3. Docs that blur deployment modes

Needs review:

- `README.md`
- `INSTALLATION.md`
- `docs/installation.md`
- `docs/configuration.md`
- `docs/production_deployment.md` / `docs/production-deployment.md`
- any docs that imply `/app/...` outside explicit Docker/container context

---

## Cleanup Strategy

### Phase 1 — Inventory and classify

For each `/app/...` reference, classify as one of:

- **Keep** — container-only and correct
- **Clarify** — docs should explicitly say container path
- **Fix** — runtime default should become native-safe or configurable

Deliverable:

- short checklist of files by category

### Phase 2 — Fix runtime defaults first

Prioritize code over docs.

Order of importance:

1. `internal/config/config.go`
2. `cmd/elemta/commands/server.go`
3. `cmd/elemta/commands/queue.go`
4. `internal/logging/logging.go`
5. `internal/auth/auth.go`
6. `internal/api/server.go`

Expected outcome:

- native runs do not accidentally default to `/app/...`
- package/systemd startup behavior is coherent
- container deployments can still override/use `/app/...`

### Phase 3 — Adjust tests

Update tests where necessary so they validate the new intended behavior rather than stale assumptions.

Expected outcome:

- tests describe the deployment model accurately
- no accidental breakage from changing runtime defaults

### Phase 4 — Tighten docs

After code behavior is settled:

- update native-install/general docs to use native paths
- keep Docker docs explicit about `/app/...`
- make dual-mode deployment story obvious

Expected outcome:

- docs stop mixing native and container assumptions
- operators are less likely to configure native installs like a container image

---

## Proposed Principles

### Principle 1

**Native defaults should prefer native-safe paths** or require explicit configuration.

### Principle 2

**Container paths should stay in container-specific docs/examples/configs**, not bleed into universal runtime fallback behavior.

### Principle 3

If a path must vary by deployment model, that should be:

- explicit
- documented
- testable

—not hidden in scattered `/app/...` fallbacks.

---

## Likely Desired End State

### Native/package installs

- config: `/etc/elemta/elemta.toml`
- queue/spool: `/var/spool/elemta`
- state: `/var/lib/elemta`
- logs: journald by default, optional `/var/log/elemta`
- runtime files: `/run/elemta`

### Container installs

- `/app/...` remains acceptable where the container image expects it
- Docker docs/examples continue to use container paths where appropriate

---

## Risks

1. breaking existing Docker assumptions by over-correcting
2. changing defaults that some tests rely on implicitly
3. mixing “general config” and “container example config” semantics

Mitigation:

- keep cleanup targeted
- preserve container-specific examples
- update tests alongside runtime fixes

---

## Concrete Next Steps

1. produce a classified `/app/...` inventory
2. patch runtime defaults on a cleanup branch
3. run `go test ./...`
4. rerun packaging smoke tests if affected
5. then do doc cleanup pass

---

## Working Summary

Elemta now has a credible native packaging path, but runtime defaults still carry too much `/app/...` baggage from the container-first model.

This cleanup effort should:

- fix the runtime behavior first
- keep container examples where they belong
- tighten docs afterward
- avoid turning the repo into a deployment-model confusion machine
