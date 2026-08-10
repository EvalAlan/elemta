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
backend = "file" # file | sqlite | postgres

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"

[queue.postgres]
dsn = "postgres://elemta:secret@127.0.0.1:5432/elemta_queue?sslmode=disable"
max_open_conns = 20
max_idle_conns = 10
conn_max_lifetime_seconds = 1800

[auth]
enabled = false
required = false
allow_deprecated_sha1 = true # migration switch for legacy {SHA}/{SSHA}
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
- `allowed_relays`
- `failed_queue_retention_hours`
- `max_workers`, `max_retries`, `max_queue_time`, `retry_schedule`
- `session_timeout` (duration string, e.g. `5m`)
- `strict_line_endings` (default `true`)
- `trusted_networks` (CIDRs; default loopback + RFC 1918)
- `spool_threshold_bytes` (default 262144)

### Trusted networks

`trusted_networks` is a list of CIDRs whose peers are treated as internal.
Internal peers take a permissive content-validation path; everyone else gets
the full checks.

Unset, it defaults to loopback and the RFC 1918 ranges the server has always
treated as internal:

```
127.0.0.0/8    ::1/128    10.0.0.0/8    172.16.0.0/12
```

Note what is *not* in that list. `192.168.0.0/16`, link-local and IPv6 ULA are
private addresses, but they are not trusted by default, because trusting them
would grant more than earlier releases did. Add them explicitly if your
deployment needs them:

```toml
trusted_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

Setting it to an empty list trusts nothing, so every connection takes the
external path. That is how the test suite reaches that path while connecting
over loopback.

A malformed entry fails at startup rather than being dropped: silently
discarding one narrows trust and starts refusing mail from a network you meant
to allow, while silently falling back to the defaults widens it.

> Earlier releases matched the peer address by string prefix. That treated
> `172.0.0.0/8` as private when only `172.16.0.0/12` is, and matched any IPv6
> address *containing* `::1` — which includes routable addresses such as
> `2001:db8::1`, since `::1` is a conventional first host address in a subnet.
> Both granted the permissive path to peers that should not have had it.
> Matching is now done on the parsed address.

### RFC 5321 line endings

`strict_line_endings` enforces CRLF termination inside `DATA`. It defaults to
`true` and is the primary defence against SMTP smuggling: a bare LF that this
server treats as ordinary message content may be interpreted as a line
terminator by a downstream server, which lets an attacker split one submission
into several messages and forge the envelope of the extra ones.

With it enabled, a bare CR or bare LF in `DATA` is rejected with
`500 5.5.2`, and `.\n` is not honoured as an end-of-data marker.

Set it to `false` only to interoperate with legacy senders that emit bare LF,
and only if you understand that this re-opens the vector.

> Prior to this being wired through, the value was always `false` in shipped
> binaries regardless of configuration, because the field was never mapped
> into the SMTP server's config. Deployments upgrading from an older build
> will see strict enforcement turn on for the first time; if that rejects
> mail you need to accept, set `strict_line_endings = false` explicitly.

### Access control (allow / deny lists)

`[access_control]` refuses connections and senders outright. It is distinct
from `trusted_networks`, which only decides how strictly a peer's *content* is
validated — this decides whether the peer may talk to the server at all.

```toml
[access_control]
enabled = true
allow_ips     = ["10.1.2.3"]
deny_ips      = ["203.0.113.0/24"]
allow_domains = ["newsletter.partner.example"]
deny_domains  = ["spam.example"]
```

- **Allow beats deny.** A host in both lists is allowed, so a known-good server
  inside a denied range can be permitted without restating the range.
- **Addresses** may be CIDR ranges or single hosts. Denied peers are refused
  with `554` before the greeting, so a blocked address costs one round trip and
  no session state.
- **Domains** are matched against the `MAIL FROM` domain *and its subdomains*,
  so `spam.example` also covers `mail.spam.example`. Matching stops before a
  bare TLD, so an entry of `com` cannot refuse everything.
- **The empty sender (`<>`) is never refused.** That is the bounce path, and
  blocking it would break delivery status notifications.
- A malformed entry stops the server at startup rather than being skipped: a
  deny rule that silently fails to load leaves you believing a network is
  blocked when it is not.

Disabled by default. Changes are read at startup, so they take effect after a
restart.

### Queue backend

- `[queue].dir`
- `[queue].backend` (`file`, `sqlite`, or `postgres`)
- `[queue.sqlite]` settings
- `[queue.postgres]` settings (`dsn`, pool sizing)

### API/web

- `[api].enabled`
- `[api].listen_addr`
- `[api].web_root`
- `[api].auth_enabled`
- `[api].auth_file`

> Use `elemta user add --file <path>` to create the users file; see the
> hardening section of [Production Deployment](production-deployment.md).
>
> **Security:** `auth_enabled` defaults to `false`. The admin API can read
> queued mail, flush queues, and rewrite configuration, so an unauthenticated
> API is only safe on loopback. The dev `docker-compose` binds it to
> `0.0.0.0`; the server logs a `SECURITY:` warning at startup in that state.
> See the hardening section of
> [Production Deployment](production-deployment.md).

### Auth

- `[auth].enabled`
- `[auth].required`
- `[auth].allow_deprecated_sha1` (default true; set false to block legacy `{SHA}`/`{SSHA}` password verification)
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

### DKIM (outbound signing)

- `[dkim].enabled`
- `[dkim].header_canonicalization` / `[dkim].body_canonicalization` (default `relaxed`)
- `[[dkim.domains]]` blocks with `domain`, `selector`, `private_key_path`, optional `headers_to_sign`

See [DKIM Signing](dkim-signing.md) for key generation, DNS setup, and details.

---

## Compatibility notes

- The code still supports some legacy nested fields under `[server]`.
- Prefer the top-level fields shown above for new configs.
- If no config file is found, Elemta starts with secure defaults where possible.

---

## Related docs

- [Installation](installation.md)
- [DKIM Signing](dkim-signing.md)
- [SMTP Server](smtp_server.md)
- [Queue Management](queue_management.md)
- [Queue Backend Runbook](queue-backend-runbook.md)
