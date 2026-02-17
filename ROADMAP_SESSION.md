# Session Roadmap: Elemta Development

## Goals
1. **Verify Main Loop Refactor**: Ensure the `internal/smtp` session loop is stable and handles the `DATA` phase correctly (verified: refactor complete, empty message fix applied).
2. **Environment Setup**: Get `docker-dev` deployment up and running for functional testing.
3. **Fix Relay Permission Blocker**: Identify why `isLocalDomain()` is rejecting local domains with "554 Relay access denied".
4. **Task Delegation**:
    - **Finn (Junior)**: Assigned to lower-level functional tests and refactor cleanup. Focus on testing the relay logic fix.
    - **Molly (Senior)**: On standby for heavy lifting in the SMTP server logic and fixing the Relay Permission blocker.
    - **Alan (Lead)**: Architecture review and race condition detection.

## Current Status
- **Branch**: `origin/develop` (ahead of `main`).
- **SMTP Server**: Modular architecture confirmed (SessionState, CommandHandler, AuthHandler, DataHandler).
- **Critical Fix (Feb 4)**: Resolved bug where empty messages were rejected due to premature line reading in the session loop.
- **Blocker**: Relay permission logic is broken (`isLocalDomain()` in `internal/smtp/session_commands.go:899`). This blocks 10 tests (8 integration + 2 functional).
- **Docker**: Environment setup in progress (`make install-dev`).

## Action Plan
1. [DONE] Verify current state of "main loop refactor" (Modular architecture is stable).
2. [IN PROGRESS] Start the `docker-dev` environment via `make install-dev`.
3. [PENDING] Verify environment health (`make status`).
4. [PENDING] **Molly**: Fix the `isLocalDomain()` logic in `internal/smtp/session_commands.go`.
5. [PENDING] **Finn**: Re-enable and run integration tests (`go test ./tests/integration -v`) once the relay fix is in.
6. [PENDING] **Alan**: Review `WorkerPool` and `ResourceManager` for potential race conditions during high-concurrency tests.

## Environment Access (once started)
- **SMTP**: `localhost:2525`
- **Web UI**: `http://localhost:8025`
- **Metrics**: `http://localhost:8080/metrics`
- **Roundcube**: `http://localhost:8026`
