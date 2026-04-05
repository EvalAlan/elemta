# Queue Backend Modularity v1 (File + SQLite)

## Status

Draft implementation spec for branch `feat/queue-db-backend`.

## Hard Requirements (locked)

1. Existing **file queue remains fully supported**.
2. Queue backend is **configurable** (`file|sqlite` at minimum).
3. **Default remains file** (no behavior change for existing installs).
4. **No implicit/automatic migration** from file queue to sqlite in v1.
5. Backend implementations must share one interface and maintain semantic parity where practical.

---

## Goals

- Introduce a pluggable queue storage backend selected by config.
- Add SQLite backend for stronger transactional claim/ack flow.
- Preserve current file-queue behavior and operational workflow.
- Keep rollout low-risk and reversible by config flip.

## Non-Goals (v1)

- Removing file backend.
- Forced migration tooling.
- Exactly-once delivery semantics.
- Multi-node distributed queue consensus.

---

## Proposed Architecture

### 1) Queue backend factory

Use one startup selection point (factory), e.g.:

- `queue.backend = "file" | "sqlite"`
- Factory returns a `StorageBackend` implementation.

If backend config is invalid: fail fast with clear field-level error.

### 2) Shared backend contract

Backends must implement a shared interface for:

- store/retrieve/delete message content + metadata
- queue transitions (`active`, `deferred`, `held`, `failed`)
- claiming work safely for workers
- retry metadata updates
- queue stats reads

Current `internal/queue` interfaces already provide most shape; v1 should extend carefully instead of creating parallel abstractions.

### 3) Semantic parity target

Across backends, preserve user-visible behavior:

- same retry schedule behavior
- same max retry semantics
- same queue state transitions
- same queue CLI/API expectations

Allowed differences in v1:

- on-disk representation
- low-level locking strategy
- backend-specific telemetry fields

---

## Configuration Proposal

### Backward-compatible config surface

Current config keeps working:

```toml
[queue]
dir = "/var/spool/elemta/queue"
```

Additive v1 fields:

```toml
[queue]
backend = "file" # default if omitted

[queue.file]
dir = "/var/spool/elemta/queue"

[queue.sqlite]
path = "/var/lib/elemta/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL" # FULL allowed
```

### Compatibility rules

- If `queue.backend` is omitted, behave as `file`.
- `queue.dir` remains valid for file backend (legacy compatibility).
- If `queue.backend = "sqlite"`, require `queue.sqlite.path`.
- Unknown backend values are validation errors.

---

## SQLite Backend (v1 scope)

Minimal schema expectation:

- message id
- queue state/status
- attempt/retry counters
- next-attempt timestamp
- lease owner + lease expiry
- metadata payload
- message content pointer or blob (implementation choice)

Operational behavior:

- at-least-once delivery
- transactional claim/update
- lease expiration returns message to eligible queue
- failed messages transition to failed/dead state after retry budget

---

## Future Backend Path: Postgres (v2+)

SQLite is the near-term implementation target. Postgres is the planned path when workload/architecture crosses single-node limits.

### Trigger criteria to start Postgres work

Start Postgres backend design/implementation when one or more are true:

1. Queue ownership must be shared by multiple active nodes.
2. HA failover requires queue continuity across host loss.
3. SQLite lock contention persists after tuning workers/batch size/timeouts.
4. Operational requirements need stronger remote backup/replication controls than local SQLite provides.
5. Throughput/backlog SLOs cannot be met with SQLite on target hardware.

### Postgres readiness checklist (before build)

- keep storage contract stable (`StorageBackend` parity tests are green)
- define lease/claim SQL semantics for concurrent workers (`FOR UPDATE SKIP LOCKED`-style)
- define migration tooling as explicit operator action (no hidden conversion)
- define rollback behavior (Postgres back to file/sqlite) and data ownership expectations

### Planned migration model (v2+)

- v2 adds `queue.backend = "postgres"` only after parity test suite exists.
- migration remains **explicit** and operator-driven.
- initial migration tool should support dry-run, id mapping validation, and cutover guardrails.
- no automatic backend flip on startup.

### Configuration placeholder (not active in v1)

```toml
[queue]
backend = "file" # file | sqlite | postgres (postgres in v2+)

[queue.postgres]
dsn = "postgres://user:pass@host:5432/elemta_queue?sslmode=verify-full"
max_open_conns = 20
max_idle_conns = 10
conn_max_lifetime = "30m"
```

---

## Rollout / Migration Plan

### Phase 1: Introduce backend switch + no-op default

- Add config parsing + validation for `queue.backend`.
- Default remains file.
- Existing configs unchanged and continue to work.

### Phase 2: Add sqlite backend behind explicit opt-in

- Implement sqlite backend.
- Activate only with `queue.backend = "sqlite"`.

### Phase 3: docs + operator runbook

- document manual switch steps
- document rollback (`sqlite -> file`) steps

### Explicitly out of scope for v1

- Auto-importing file queue into sqlite.
- Auto-cutover or dual-write migration.

Manual migration can be a later, explicit feature with dry-run + validation.

---

## Acceptance Criteria

### A. File backend safety (must pass)

- Existing file queue tests pass unchanged.
- Default startup path uses file backend with no config changes.
- No file layout or permission regressions.
- Queue CLI/API behavior unchanged when backend=file.

### B. Configurability (must pass)

- `queue.backend` accepted with `file|sqlite`.
- Missing/invalid sqlite config fails startup with clear error.
- Omitted backend uses file by default.

### C. SQLite backend baseline (must pass)

- enqueue -> process -> success path works.
- retry path works with existing retry schedule semantics.
- failed-state transition at max retries works.
- worker claim path avoids duplicate active claims under concurrency.

### D. No auto-migration (must pass)

- Switching backend does not implicitly move old queue data.
- Docs clearly state manual migration is separate and optional.

---

## Test Matrix (minimum)

1. **Config default test**: no backend specified => file selected.
2. **Config validation test**: invalid backend value rejected.
3. **Config validation test**: sqlite backend without path rejected.
4. **File regression test**: existing queue workflow unchanged.
5. **File security test**: permissions/atomicity expectations unchanged.
6. **SQLite happy-path test**: enqueue/claim/ack.
7. **SQLite retry test**: deferred schedule and retry count updates.
8. **SQLite failure test**: exceeds retries -> failed queue/state.
9. **Concurrency test**: multiple workers cannot hold same active lease.
10. **Lease expiry test**: abandoned inflight messages become eligible again.
11. **Backend switch test**: explicit switch required; no implicit migration.

---

## PR Breakdown (small chunks)

### PR1: Config + factory wiring

- Add `queue.backend` and backend-specific config structs.
- Validation rules and defaults.
- Backend factory integration.
- No sqlite implementation yet; default file path remains unchanged.

### PR2: SQLite backend core

- Add sqlite storage backend implementation.
- Add schema creation/migration bootstrap.
- Basic claim/ack/retry/fail paths.

### PR3: Test coverage + parity checks

- Add matrix tests above.
- Add explicit file-backend regression guard tests.
- Add concurrency/lease tests for sqlite.

### PR4: Docs + operator guidance

- Update `docs/configuration.md` and queue docs.
- Add backend switching runbook.
- Document no-auto-migration constraint and rollback steps.

---

## Risks / Guardrails

- **Risk:** subtle behavior drift between backends.
  - **Guardrail:** parity tests at queue-manager behavior layer.
- **Risk:** sqlite lock contention under high worker counts.
  - **Guardrail:** timeout tuning + conservative default workers.
- **Risk:** accidental migration assumptions by operators.
  - **Guardrail:** loud docs + startup warnings when backend flips.

---

## Definition of Done (v1)

Done when:

- file backend remains default and non-regressed,
- sqlite backend is opt-in and operational,
- backend selection is validated and explicit,
- no automatic migration exists,
- docs/tests enforce these guarantees.