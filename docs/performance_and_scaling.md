# Performance and Scaling

This guide focuses on knobs that are actively used in current runtime paths.

## Primary scaling levers

## 1) Queue processor concurrency

```toml
[queue_processor]
enabled = true
interval = 10
workers = 5
```

- Increase `workers` when delivery backlog grows and downstream can absorb more concurrency.
- Lower `interval` for faster queue polling (higher overhead).

## 2) Queue backend choice

```toml
[queue]
backend = "file"   # default
# or
backend = "sqlite"
```

- `file`: simple baseline, easy local inspection.
- `sqlite`: better metadata operations and storage introspection via `/api/queue/storage`.

## 3) Resource limits

```toml
[resources]
max_connections = 1000
max_connections_per_ip = 100
rate_limit_window = 60
max_requests_per_window = 5000
```

Tune these to match expected load profile and abuse tolerance.

## 4) Distributed front-end scaling

Use compose overlay for multiple SMTP nodes plus Valkey-backed coordination:

```bash
docker compose \
  -f deployments/compose/docker-compose.yml \
  -f deployments/compose/docker-compose-multinode.yml \
  up -d
```

## Observability-first tuning

Track before/after values for:

- queue depth and age (`/api/queue/stats`)
- delivery success/failure ratios (`/api/stats/delivery`)
- auth failures and connection pressure (logs + metrics)

## Load testing

```bash
make test-load
```

Use controlled bursts and increase gradually; avoid changing multiple major knobs at once.

## Practical tuning order

1. Fix correctness issues first (queue stuck, auth errors, TLS failures).
2. Tune queue workers/interval.
3. Tune resource limits.
4. Evaluate backend choice (`file` vs `sqlite`).
5. Scale horizontally only after single-node tuning is stable.

## Related docs

- [Queue Management](queue_management.md)
- [Rate Limiting](rate-limiting.md)
- [Multinode Deployment](multinode-deployment.md)
