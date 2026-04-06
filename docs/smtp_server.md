# SMTP Server

This document covers the current SMTP server behavior and runtime knobs.

---

## Start the server

```bash
./bin/elemta server --config ./config/elemta.toml
```

Useful runtime flags:

- `--dev` — development mode (debug-friendly behavior)
- `--no-auth-required` — disables auth requirement at runtime
- `--port <n>` — overrides listen port

Example:

```bash
./bin/elemta server --config ./config/dev.toml --dev --port 2525
```

---

## Core runtime settings

From config (TOML):

```toml
hostname = "mail.example.com"
listen_addr = ":2525"
max_size = 52428800
local_domains = ["example.com", "localhost"]

[queue]
dir = "/var/spool/elemta/queue"
backend = "file"

[auth]
enabled = true
required = false
datasource_type = "ldap"

[tls]
enabled = false
enable_starttls = true
cert_file = ""
key_file = ""
```

---

## SMTP command support (current)

Elemta supports standard SMTP flow and common extensions, including:

- `HELO` / `EHLO`
- `MAIL FROM`
- `RCPT TO`
- `DATA`
- `BDAT` (CHUNKING)
- `RSET`, `NOOP`, `QUIT`
- `STARTTLS` (when enabled)
- `AUTH` (when enabled)
- `XDEBUG` (dev mode)

Common advertised extensions include:

- `8BITMIME`
- `SMTPUTF8`
- `ENHANCEDSTATUSCODES`
- `PIPELINING`
- `CHUNKING`
- `DSN`
- `REQUIRETLS` (when TLS context allows)

---

## Queue processor integration

The SMTP server enqueues accepted mail and the queue processor handles delivery attempts.

```toml
[queue_processor]
enabled = true
interval = 10
workers = 5
debug = false
```

---

## Relay behavior at a glance

- Local-domain delivery uses configured `local_domains`.
- External relay behavior is controlled by auth requirements and delivery config.
- For production, do not run open relay settings.

---

## Quick smoke test

```bash
telnet localhost 2525
```

Then execute a basic SMTP session (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`).

---

## Related docs

- [Configuration](configuration.md)
- [Queue Management](queue_management.md)
- [Testing](testing.md)
- [Troubleshooting](troubleshooting.md)
