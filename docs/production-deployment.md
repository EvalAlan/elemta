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

### The admin API is unauthenticated by default — this matters most

`[api].auth_enabled` defaults to **false**, and the shipped `docker-compose`
runs the web service bound to `0.0.0.0`. In that combination, anyone who can
reach the port can:

- read any queued message — full content and headers
- flush queues (delete mail) and requeue
- read and rewrite server configuration
- send mail through the test endpoint

There is no read-only mode. Treat the API/web port exactly as you would a
root shell on the mail server.

The server now logs a `SECURITY:` warning at startup when it binds to anything
other than loopback with auth disabled — do not ignore it. Choose one of:

1. **Bind to loopback.** Set `[api].listen_addr = "127.0.0.1:8025"` (or the
   `--listen` flag) and reach it via SSH tunnel or a co-located proxy. This is
   the right default for most deployments.
2. **Enable authentication.** Set `[api].auth_enabled = true` and provide an
   auth file (`[api].auth_file`). Required if the port is reachable by anyone
   you do not fully trust.
3. **Front it with an authenticating reverse proxy** (mTLS, OIDC, or basic
   auth over TLS) and bind the app to loopback behind it.

The dev stack ships insecure on purpose — it is a single-host demo. A
production deployment that copies the dev `docker-compose` verbatim inherits an
open admin API. Do not.

### TLS

- Provide real certificate and key paths; do not run STARTTLS-only in
  production without a valid chain.
- Cipher-suite ordering is controlled by the Go runtime (server-side ordering
  preferences are ignored by modern Go); rely on the runtime's secure defaults
  rather than trying to pin an order.

---

## 5) Content scanning

Antivirus and antispam are plugins. Enable the ones you run, and give them
addresses — the defaults assume `localhost`, which is wrong wherever the
scanners are separate containers or hosts.

```toml
[antivirus]
enabled = true
reject_on_failure = false

[antivirus.clamav]
enabled = true
address = "clamav.internal:3310"
timeout = 30
scan_limit = 26214400

[antispam]
enabled = true
reject_on_spam = false

[antispam.rspamd]
enabled = true
address = "http://rspamd.internal:11333"
timeout = 30
threshold = 6.0
```

Both `[antivirus].enabled` and `[antivirus.clamav].enabled` must be true; the
section gate and the per-scanner gate are both honoured.

### What the settings mean

- **`reject_on_failure`** — a scanner that cannot be reached delivers the
  message unscanned rather than refusing it. Leave it `false` unless you would
  rather lose mail than accept it unscanned; a scanner outage becomes a mail
  outage otherwise.
- **`reject_on_spam`** — the engine decides what is spam against its own
  threshold; this decides whether that verdict refuses the message. With it
  `false`, spam is delivered carrying `X-Spam-*` headers for downstream
  filtering. A virus verdict always refuses, regardless.
- **`scan_limit`** — how much of a message is sent to the scanner. Messages are
  streamed from the spool, so this bounds scanner work rather than memory.

If no scanner is reachable, the server logs a warning at startup and delivers
mail unscanned:

```
No antivirus scanner is available; messages will be delivered unscanned for viruses
```

Treat that line as an alert. Silence there previously looked identical to
working scanners.

### Latency

Scanning costs a network round trip per message per engine, and the two run
concurrently. Rspamd's optional lookups can dominate that:

- `fuzzy_check` queries rspamd.com over UDP for every message. Measured on a
  development stack it added roughly 4.3 seconds to about 5% of messages, cut
  throughput by more than half, and made it swing eightfold between runs.
- DNS blocklists (`rbl`, `surbl`) behave badly against a resolver that answers
  for names which should not exist — rspamd cannot then tell a working
  blocklist from a broken one.

Both are genuinely useful against bulk mail. Keep them if you want them, but
size for the latency and make sure Rspamd has a resolver that returns NXDOMAIN
properly. The development stack disables them for reproducibility, via
`docker/rspamd/override.d/`; those overrides are **not** intended for
production.

---

## 6) Upgrades and rollback

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

## 7) Queue backend caveat

Changing `queue.backend` does **not** migrate existing queued messages automatically.

Operational switching steps are documented in:

- [Queue Backend Runbook](queue-backend-runbook.md)
