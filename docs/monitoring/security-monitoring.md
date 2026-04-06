# Security Monitoring

This guide covers operator checks for spam/virus and auth security signals.

## Scope

Key security-related sources in the repo:

- Elemta runtime/logs
- ClamAV integration paths
- Rspamd integration paths
- Prometheus + Grafana monitoring assets

## Bring up stack (example)

```bash
# Core mail stack
docker compose -f deployments/compose/docker-compose.yml up -d

# Monitoring stack
docker compose -f deployments/compose/docker-compose-monitoring.yml up -d
```

## What to watch

### Queue and delivery health

```bash
curl -s http://127.0.0.1:8025/api/queue/stats | jq
curl -s http://127.0.0.1:8025/api/stats/delivery | jq
```

### Runtime logs

```bash
docker compose -f deployments/compose/docker-compose.yml logs -f elemta
```

Look for:

- repeated delivery failures
- abnormal reject/tempfail spikes
- auth failure bursts

### Monitoring UIs

- Prometheus: inspect time-series and alert state
- Grafana: inspect security and delivery dashboards

## Baseline operational checks

1. SMTP/API endpoints healthy.
2. Queue is draining (not growing indefinitely).
3. No sustained auth failure spikes.
4. Spam/virus rejects are explainable and within expected range.
5. Alerts are routed and actionable.

## Related docs

- [Monitoring](README.md)
- [Logging](../logging.md)
- [Troubleshooting](../troubleshooting.md)
