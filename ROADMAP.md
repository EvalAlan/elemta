# Elemta Roadmap (Production-Ready + Best-in-Class Track)

This roadmap is based on the comprehensive audit in `docs/audits/2026-04-05-comprehensive-audit.md`.

## Phase 0 — Stabilization (0-2 weeks)

**Goal:** Remove immediate reliability/security risk.

- [ ] Upgrade Go toolchain/runtime to latest patch (address stdlib vulns from govulncheck)
- [ ] Resolve remaining race-test failures in `internal/smtp` (memory manager suite)
- [ ] Add race smoke lanes to CI for critical SMTP/session paths
- [ ] Triage and fix high-signal gosec findings (true positives first)
- [ ] Publish security/contact + contribution docs (done)

## Phase 1 — Operational Hardening (2-6 weeks)

**Goal:** Make production operations predictable.

- [ ] Queue SLOs + alert thresholds (latency, retry depth, failure rate)
- [ ] Backpressure/load-shed policy under SMTP spikes
- [ ] API auth hardening defaults and explicit deployment profiles
- [ ] TLS policy profile matrix (minimum/recommended/strict)
- [ ] Disaster recovery runbooks (queue corruption, sqlite lock contention, rollback)

## Phase 2 — Product Quality (6-12 weeks)

**Goal:** Increase confidence and reduce maintenance drag.

- [ ] Consolidate/modernize test strategy docs and scripts
- [ ] Remove/retire stale docs and obsolete examples
- [ ] Expand integration tests for queue backend switching + failure recovery
- [ ] Add contract tests for API/web queue surfaces
- [ ] Improve perf CI with repeatable SMTP load baselines and regressions guard

## Phase 3 — Feature Leadership (quarterly)

**Goal:** Differentiate on reliability, observability, and deliverability.

- [ ] Pluggable queue backends beyond sqlite/file (with migration tooling)
- [ ] Advanced delivery policies (adaptive retry, per-domain QoS)
- [ ] First-class operator UX (storage insights, remediation hints)
- [ ] Better multi-node story with clear consistency/failure semantics
- [ ] Public benchmark suite + reproducible performance profiles

## Acceptance criteria for "production-ready"

- No known reachable critical/high vulnerabilities in release branch
- CI includes lint, unit, integration, and targeted race/security checks
- Documented backup/restore + rollback path for every storage backend
- Stable operational runbooks for common incidents
- Up-to-date contributor/security/support docs and issue templates
