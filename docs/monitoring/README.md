# Monitoring

Monitoring assets are in the repository under:

- `monitoring/prometheus/`
- `monitoring/grafana/`
- `monitoring/alertmanager/`

## Start monitoring stack

From repo root:

```bash
docker compose -f deployments/compose/docker-compose-monitoring.yml up -d
```

## Endpoints

- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`

## Stop stack

```bash
docker compose -f deployments/compose/docker-compose-monitoring.yml down
```

## Logs

```bash
docker compose -f deployments/compose/docker-compose-monitoring.yml logs -f
```

## Dashboards and rules

- Grafana dashboards: `monitoring/grafana/dashboards/`
- Prometheus rules: `monitoring/prometheus/rules/`
- Alertmanager config: `monitoring/alertmanager/alertmanager.yml`

## Security-specific notes

For ClamAV/Rspamd-focused checks and operator workflow, see:

- [Security Monitoring](security-monitoring.md)
