# Rate Limiting

Two things limit clients and mail:

1. SMTP/resource manager limits (`[resources]`)
2. Abuse protection (`[abuse]`, edited in the admin console), for connections,
   failed sign-ins and message counts across every service

## 1) SMTP/resource limits (primary runtime path)

```toml
[resources]
max_connections = 1000
max_connections_per_ip = 100
connection_timeout = 30
session_timeout = 300
idle_timeout = 120
rate_limit_window = 60
max_requests_per_window = 5000
```

Distributed mode (Valkey-backed checks) is configured via resource settings in the runtime config path.

## 2) Abuse protection

Connection, sign-in and message limits, shared by SMTP, IMAP, POP3,
ManageSieve, webmail and the console, and changed without a restart. The
settings and what each one does are in the admin console.

## `[rate_limiter]` is not enforced

The section still loads, so existing files keep working, but nothing in the
mail path reads it: the built-in rate limiter plugin isn't loaded. The console
no longer offers a switch for it. Set the limits with the two above.

## Operational checks

```bash
# SMTP/API health
curl -s http://127.0.0.1:8025/api/health | jq

# Queue pressure (often first symptom of throttling/misconfig)
curl -s -u admin http://127.0.0.1:8025/api/queue/stats | jq
```

## Tuning guidance

- Start permissive in development.
- Tighten per-IP + auth limits for internet-facing production.
- Use Valkey-backed distribution when running multi-node traffic fronts.
- Re-check queue growth and reject rates after every limit change.

## Related docs

- [Configuration](configuration.md)
- [Queue Management](queue_management.md)
- [Troubleshooting](troubleshooting.md)
