# Elemta Configuration

Elemta runtime configuration is loaded from **TOML**.

> `.conf` filenames are still searched for compatibility, but the parser expects TOML content.

---

## Config file discovery order

When `--config` is not provided, Elemta searches common paths in order:

1. `./elemta.toml`
2. `./elemta.conf`
3. `./config/elemta.toml`
4. `./config/elemta.conf`
5. `../config/elemta.toml`
6. `../config/elemta.conf`
7. `$HOME/.config/elemta/elemta.toml`
8. `$HOME/.elemta.toml`
9. `$HOME/.elemta.conf`
10. `/etc/elemta/elemta.toml`
11. `/etc/elemta/elemta.conf`

You can always pin a file explicitly:

```bash
./bin/elemta server --config ./config/elemta.toml
```

---

## Minimal working config

```toml
hostname = "mail.example.com"
listen_addr = ":2525"
max_size = 52428800
local_domains = ["example.com", "localhost"]

[queue]
dir = "/var/spool/elemta/queue"
backend = "file" # file | sqlite

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"

[auth]
enabled = false
required = false
datasource_type = "file"
datasource_path = "/etc/elemta/users.txt"

[delivery]
mode = "lmtp"
host = "127.0.0.1"
port = 2424
timeout = 30
max_retries = 3
retry_delay = 60

[metrics]
enabled = true
listen_addr = ":8080"

[api]
enabled = true
listen_addr = "127.0.0.1:8025"
web_root = "./web/static"
auth_enabled = false
auth_file = ""

[queue_processor]
enabled = true
interval = 10
workers = 5
debug = false

[logging]
type = "console"
level = "info"
format = "text"
file = "/var/log/elemta/elemta.log"
```

---

## Key sections used in current code

### Top-level SMTP/runtime fields

- `hostname`
- `listen_addr`
- `max_size`
- `local_domains`
- `failed_queue_retention_hours`

### Queue backend

- `[queue].dir`
- `[queue].backend` (`file` or `sqlite`)
- `[queue.sqlite]` settings

### API/web

- `[api].enabled`
- `[api].listen_addr`
- `[api].web_root`
- `[api].auth_enabled`
- `[api].auth_file`

### Auth

- `[auth].enabled`
- `[auth].required`
- datasource fields (`datasource_type`, `datasource_path`, `datasource_host`, etc.)

### Delivery

- `[delivery].mode`
- `[delivery].host`
- `[delivery].port`
- retry/timeouts

### Metrics

- `[metrics].enabled`
- `[metrics].listen_addr`

### TLS

- `[tls].enabled`
- `[tls].enable_starttls`
- `[tls].cert_file`
- `[tls].key_file`
- optional `[tls.letsencrypt]`

---

## Compatibility notes

- The code still supports some legacy nested fields under `[server]`.
- Prefer the top-level fields shown above for new configs.
- If no config file is found, Elemta starts with secure defaults where possible.

---

## Related docs

- [Installation](installation.md)
- [SMTP Server](smtp_server.md)
- [Queue Management](queue_management.md)
- [Queue Backend Runbook](queue-backend-runbook.md)
