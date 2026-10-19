# Elemta Installation Guide

This guide reflects the **current** install and run paths in this repository.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`)
- Go (for source builds)
- Git

---

## The setup wizard

```bash
git clone https://github.com/EvalAlan/elemta.git
cd elemta
make install
```

`make install` (or `make setup`) runs `scripts/setup.sh`, which asks what you
are setting up:

1. **A development stack on this machine.** It runs `make install-dev`, or
   `make install-dev-full` if you also want the scanners and Roundcube.
2. **A mail server for a real domain, on an internet-facing host.** It:
   - checks the prerequisites, memory and disk;
   - checks that the domain's A record points at this host, and checks the MX
     record, reverse DNS, outbound port 25 and that the mail ports are free;
   - turns off Docker's userland proxy, which would otherwise make the server
     an open relay over IPv6;
   - opens the mail and web ports in firewalld or ufw, and installs the Docker
     port guard;
   - optionally lets one IP address reach the admin console over HTTPS;
   - deploys with `scripts/cloud-deploy.sh`;
   - creates the admin console login and your first mailbox.

   Each host change is explained and asks first.
   `scripts/setup.sh --check` runs the checks and changes nothing, which is
   useful before pointing DNS at a new host. `--yes` takes every default, for
   unattended installs. The rest of this guide covers the steps the wizard runs,
   for doing them by hand.

## 1) Docker-based development setup

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
