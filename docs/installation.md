# Elemta Installation Guide

This guide reflects the **current** install and run paths in this repository.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`)
- Go (for source builds)
- Git

---

## 1) Recommended: Docker-based development setup

Clone and enter the repo:

```bash
git clone https://github.com/EvalAlan/elemta.git
cd elemta
```

### Minimal dev stack (fast)

```bash
make install-dev
```

Starts the core services and bootstraps local dev defaults: the Elemta MTA, the admin console, the mailbox service (two replicas behind HAProxy, with Postgres), webmail, LDAP, Valkey and a caching DNS resolver. Webmail is on http://localhost:8027 (`user@example.com` / `password`), the admin console on http://localhost:8025, SMTP on 2525, submission on 2587 and IMAP on 993.

### Full dev stack

```bash
make install-dev-full
```

Adds ClamAV and Rspamd scanning, and Roundcube on http://localhost:8026 as a second webmail client reading the same mailboxes.

Other variants: `make install-dev-postgres` (Postgres queue), `make install-dev-mailauth` (outbound DKIM signing and ARC sealing lab, delivering to a local sink), and `make install-dev-bench` (delivers to a discarding LMTP sink, for benchmarks only).

### Day-to-day commands

```bash
make up
make down
make restart
make status
make logs
make logs-elemta
```

Compose file used by Make targets:

- `deployments/compose/docker-compose.yml`

---

## 2) Build from source

Build all binaries:

```bash
make build
```

Output binaries:

- `bin/elemta` (main server/ops CLI)
- `bin/elemta-queue` (queue status utility)
- `bin/elemta-cli` (lightweight helper CLI)

Run server directly:

```bash
./bin/elemta server --config ./config/elemta.toml
```

Run web/API directly:

```bash
./bin/elemta web --config ./config/elemta.toml
```

---

## 3) Quick validation after install

```bash
make status
make test
```

Optional targeted concurrency checks:

```bash
make test-race-smoke
```

---

## 4) Other deployment models

### Production (Docker Compose over SSH)

See [Production Deployment](production-deployment.md).

### Native packages (RPM/DEB, proposed)

Not shipped yet. The intended layout is in
[Native Install Spec v1](native-install-spec-v1.md).

---

## Notes

- Configuration is TOML-based. See [Configuration](configuration.md).
- Queue backend can be `file`, `sqlite`, `postgres` or `indexedfs`. See [Queue Management](queue_management.md) and [Queue Backend Runbook](queue-backend-runbook.md).
