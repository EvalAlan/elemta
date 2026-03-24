# Runtime Path Inventory (`/app/...`)

## Purpose

This is the Phase 1 classification pass for `/app/...` references in the repo.

The goal is to sort references into:

- **Keep** — container-specific and correct
- **Clarify** — acceptable, but docs/examples should be more explicit about being container-specific
- **Fix** — runtime defaults or generally misleading references that should be changed

This inventory is intentionally biased toward practical cleanup, not theoretical purity.

---

## Summary

### Keep

These are container-native references and should generally stay:

- Docker deployment docs
- Kubernetes/container exec examples
- container-focused example configs under `config/`
- packaging Docker smoke-test harness references to `/app/logs`
- security tests intentionally validating `/app/...` paths

### Clarify

These likely remain valid, but should be labeled more explicitly as container-specific:

- general configuration docs that currently show `/app/...` without saying “container example”
- plugin docs that imply `/app/plugins` as the general path instead of a container path
- production deployment docs that mix native and container examples too closely

### Fix

These are the important ones:

- core runtime defaults in code
- command-layer fallbacks
- logging/auth/api fallback paths that behave as if `/app/...` is the universal runtime environment
- tests that encode stale defaults rather than explicit container-mode behavior

---

## FIX — Runtime defaults / behavior

These should be addressed first.

### `internal/config/config.go`

Current issues:

- default queue dir falls back to `/app/queue`
- default plugins dir falls back to `/app/plugins`
- config default behavior still reflects container-first assumptions

Why this matters:

- native/package installs should not silently inherit container image layout
- packaging work already exposed how these defaults leak into host behavior

Status:

- **Fix**

---

### `cmd/elemta/commands/server.go`

Current issues:

- command-layer fallback queue dir uses `/app/queue`

Why this matters:

- fallback behavior in the server command should not bypass native-safe defaults

Status:

- **Fix**

---

### `cmd/elemta/commands/queue.go`

Current issues:

- queue command default uses `/app/queue`

Why this matters:

- CLI behavior should not assume container path layout as the general default

Status:

- **Fix**

---

### `internal/logging/logging.go`

Current issues:

- logger initialization tries to create `/app/logs`
- default log file opens `/app/logs/elemta.log`

Why this matters:

- native/package runs should not default to container log paths
- journald/default native logging model now exists

Status:

- **Fix**

---

### `internal/auth/auth.go`

Current issues:

- sqlite auth DB fallback uses `/app/config/auth.db`
- file auth fallback uses `/app/config/users.txt`

Why this matters:

- auth defaults should not assume a container filesystem unless explicitly in container mode

Status:

- **Fix**

---

### `internal/api/server.go`

Current issues:

- auth/log file defaults reference `/app/config/users.txt` and `/app/logs/*`
- API/UI/log-view assumptions still smell container-first

Why this matters:

- API/runtime tooling should not present `/app/...` as the implicit general path set

Status:

- **Fix**

---

## FIX — Tests encoding stale defaults

These should be adjusted after runtime behavior is corrected.

### `internal/config/config_validation_test.go`

Current issues:

- expects queue dir `/app/queue`
- expects plugins dir `/app/plugins`

Why this matters:

- these tests currently reinforce container defaults as if they are universal defaults

Status:

- **Fix after runtime changes**

---

## KEEP — Container-specific and correct

These are fine to leave alone for now.

### Docker / container docs

Examples:

- `docs/docker_deployment.md`
- `docs/integration_deployment.md`
- container exec examples in `docs/cli.md`
- Kubernetes/container mount examples in `docs/production-deployment.md`

Why:

- these are explicitly container/runtime-image oriented
- `/app/...` is correct there

Status:

- **Keep**

---

### Example container configs under `config/`

Examples:

- `config/elemta.toml`
- `config/elemta-starttls-test.toml`
- `config/elemta-with-metrics.toml`
- `config/elemta-letsencrypt-demo.toml`

Why:

- these appear to be container/dev-oriented example configs
- changing them blindly would risk mixing native and container stories

Status:

- **Keep for now**
- later improvement: rename or label more clearly as container examples if needed

---

### Security tests intentionally using `/app/...`

Examples:

- `internal/config/security_test.go`
- `internal/config/file_security_test.go`
- `internal/config/malicious_config_test.go`

Why:

- these are validating path handling and attack cases
- `/app/...` is a legitimate path prefix to test even if it is not the native default

Status:

- **Keep**

---

### Packaging Docker test harness

Example:

- `packaging/docker/test-package-runtime.sh`

Why:

- this is test-only scaffolding
- `/app/logs` is being used to satisfy current runtime assumptions during smoke tests
- should probably be revisited after runtime defaults are cleaned up

Status:

- **Keep for now**

---

## CLARIFY — Docs/examples that should be more explicit

These are not necessarily wrong, but they blur deployment modes.

### `docs/configuration.md`

Current issue:

- uses `/app/config` examples without always framing them as container-specific

Status:

- **Clarify**

---

### `docs/plugin-architecture.md`
### `docs/plugin-development.md`

Current issue:

- plugin directory examples use `/app/plugins`
- may read like universal guidance instead of container layout

Status:

- **Clarify**

---

### `docs/production-deployment.md`

Current issue:

- mixes native-looking and container-specific material
- `/etc/elemta` host paths are mounted into `/app/...` container paths, which is valid, but it should be clearly labeled as container deployment behavior

Status:

- **Clarify**

---

### `docs/environment_configuration.md`
### `docs/integration_config.md`

Current issue:

- several examples use `/app/...` paths without consistently distinguishing deployment model

Status:

- **Clarify**

---

## Recommended Work Order

### First

Fix runtime/code defaults:

1. `internal/config/config.go`
2. `cmd/elemta/commands/server.go`
3. `cmd/elemta/commands/queue.go`
4. `internal/logging/logging.go`
5. `internal/auth/auth.go`
6. `internal/api/server.go`

### Second

Adjust tests that encode old defaults:

- `internal/config/config_validation_test.go`
- related config/default tests as needed

### Third

Do a smaller doc clarification pass:

- `docs/configuration.md`
- `docs/plugin-architecture.md`
- `docs/plugin-development.md`
- `docs/production-deployment.md`
- `docs/environment_configuration.md`
- `docs/integration_config.md`

---

## Working Conclusion

The real cleanup target is **not** “remove `/app/...` from the repo.”

The real cleanup target is:

- stop using `/app/...` as the implicit universal runtime default
- keep `/app/...` where it is explicitly container-specific
- make the docs honest about which deployment model they are describing
