# Production Deployment

This is the maintained production-oriented deployment guide for the current codebase.

## Deployment models

1. **Containerized** (recommended operationally for this repo)
2. **Native package/systemd** (tracked in [Native Install Spec v1](native-install-spec-v1.md))

---

## 1) Containerized production baseline

Use the compose assets in:

- `deployments/compose/docker-compose.yml`

### Steps

1. Prepare host paths for persistent data (queue/logs/config).
2. Provide a production TOML config file.
3. Bring stack up with docker compose.
4. Validate SMTP, API health, and queue/storage endpoints.

Example:

```bash
docker compose -f deployments/compose/docker-compose.yml up -d
```

---

## 2) Minimal production TOML profile

```toml
hostname = "mail.example.com"
listen_addr = ":25"
max_size = 52428800
local_domains = ["example.com"]
failed_queue_retention_hours = 72

[queue]
dir = "/var/spool/elemta/queue"
backend = "sqlite"

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"

[auth]
enabled = true
required = true
datasource_type = "ldap"

[tls]
enabled = true
enable_starttls = true
cert_file = "/etc/elemta/certs/fullchain.pem"
key_file = "/etc/elemta/certs/privkey.pem"

[api]
enabled = true
listen_addr = "127.0.0.1:8025"
web_root = "./web/static"
auth_enabled = true
auth_file = "/etc/elemta/users.txt"

[metrics]
enabled = true
listen_addr = "127.0.0.1:8080"

[queue_processor]
enabled = true
interval = 10
workers = 5
```

---

## 3) Validation checklist

```bash
# SMTP reachable
nc -vz 127.0.0.1 25

# API health
curl -s http://127.0.0.1:8025/api/health | jq

# Queue stats
curl -s http://127.0.0.1:8025/api/queue/stats | jq

# Queue storage backend info
curl -s http://127.0.0.1:8025/api/queue/storage | jq
```

---

## 4) Hardening checklist

- Keep API bound to loopback (`127.0.0.1`) unless explicitly proxied.
- Require SMTP auth for relay paths where appropriate.
- Enforce TLS with valid cert/key paths.
- Store config/auth/queue paths with least-privilege permissions.
- Keep regular backups of queue data and config.
- Run `make test` / `make lint` before deployment changes.

---

## 5) Upgrades and rollback

### Upgrade

1. Pull new code/image.
2. Run baseline checks (`make test`, smoke tests).
3. Roll deployment.
4. Validate queue backend + health endpoints.

### Rollback

1. Re-deploy previous image/build.
2. Keep queue backend setting unchanged unless rollback explicitly requires backend switch.
3. Re-validate `/api/queue/storage` and `/api/health`.

---

## 6) Queue backend caveat

Changing `queue.backend` does **not** migrate existing queued messages automatically.

Operational switching steps are documented in:

- [Queue Backend Runbook](queue-backend-runbook.md)
