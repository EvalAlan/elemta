# Docker Compose Guide

This page is the Docker entrypoint for the current repo.

Canonical compose files live in:

- `deployments/compose/`

## Stacks

### Main dev stack

```bash
docker compose -f deployments/compose/docker-compose.yml up -d
```

### Main + multinode overlay

```bash
docker compose \
  -f deployments/compose/docker-compose.yml \
  -f deployments/compose/docker-compose-multinode.yml \
  up -d
```

### Monitoring stack

```bash
docker compose -f deployments/compose/docker-compose-monitoring.yml up -d
```

### CLI/test helpers

- `deployments/compose/docker-compose-cli.yml`
- `deployments/compose/docker-compose-test.yml`

## Useful commands

```bash
# Service status
docker compose -f deployments/compose/docker-compose.yml ps

# Follow logs
docker compose -f deployments/compose/docker-compose.yml logs -f

# Stop
docker compose -f deployments/compose/docker-compose.yml down
```

## Notes

- `make install-dev` / `make install-dev-full` are the fastest supported setup paths.
- For deployment details, see [Production Deployment](../production-deployment.md).
- For queue/backend operations, see [Queue Backend Runbook](../queue-backend-runbook.md).
