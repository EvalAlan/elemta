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
git clone https://github.com/busybox42/elemta.git
cd elemta
```

### Minimal dev stack (fast)

```bash
make install-dev
```

Starts the core services (Elemta + web + Dovecot + LDAP + Valkey) and bootstraps local dev defaults.

### Full dev stack

```bash
make install-dev-full
```

Includes extra services (e.g. ClamAV, Rspamd, Roundcube) in addition to the core stack.

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

### Kubernetes

Manifest examples are in `k8s/`.

```bash
kubectl apply -f k8s/
```

See also: `k8s/README.md`.

### Native packages (RPM/DEB direction)

For path/layout and packaging direction, see:

- [Native Install Spec v1](native-install-spec-v1.md)

---

## Notes

- Configuration is TOML-based. See [Configuration](configuration.md).
- Queue backend can be `file` or `sqlite`. See [Queue Management](queue_management.md) and [Queue Backend Runbook](queue-backend-runbook.md).
