# Rate Limiting

Elemta currently exposes rate limiting in two places:

1. SMTP/resource manager limits (`[resources]`)
2. Rate-limiter plugin config (`[rate_limiter]`), used by web/config surfaces and plugin-oriented flows

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

## 2) Rate limiter plugin config

```toml
[rate_limiter]
enabled = true
max_connections_per_ip = 100
connection_rate_per_minute = 1000
connection_burst_size = 200
max_messages_per_minute = 300
max_messages_per_hour = 10000
max_auth_attempts_per_minute = 20
auth_lockout_duration = "5m"
valkey_url = ""
valkey_key_prefix = "elemta:ratelimit:"
```

This config is surfaced in API config endpoints and used where plugin-style rate limiting is enabled.

## Operational checks

```bash
# SMTP/API health
curl -s http://127.0.0.1:8025/api/health | jq

# Queue pressure (often first symptom of throttling/misconfig)
curl -s http://127.0.0.1:8025/api/queue/stats | jq
```

## Tuning guidance

- Start permissive in development.
- Tighten per-IP + auth limits for internet-facing production.
- Use Valkey-backed distribution when running multi-node traffic fronts.
- Re-check queue growth and reject rates after every limit change.

## Related docs

- [Multinode Deployment](multinode-deployment.md)
- [Performance and Scaling](performance_and_scaling.md)
- [Troubleshooting](troubleshooting.md)
