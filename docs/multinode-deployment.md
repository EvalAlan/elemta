# Multinode Deployment

This guide covers the current compose-based multi-node pattern in this repo.

## What it is

`deployments/compose/docker-compose-multinode.yml` adds extra Elemta nodes on top of the main compose stack.

Primary use case:

- distributed front-door SMTP capacity
- shared Valkey-backed rate limiting signals

## Start multi-node stack

```bash
docker compose \
  -f deployments/compose/docker-compose.yml \
  -f deployments/compose/docker-compose-multinode.yml \
  up -d
```

## Verify nodes

```bash
docker compose \
  -f deployments/compose/docker-compose.yml \
  -f deployments/compose/docker-compose-multinode.yml \
  ps
```

Typical exposed ports in this setup:

- node0 SMTP: `2525`
- node1 SMTP: `2526`
- node2 SMTP: `2527`

## Validation

A repo test helper exists for this path:

```bash
python3 tests/test-multinode-valkey.py
```

## Important caveats

- This compose setup is primarily a **single-host demo/dev topology**.
- It is not a turnkey cross-host distributed queue design.
- Backend and queue ownership decisions still need explicit operational design in production.

## Related docs

- [Rate Limiting](rate-limiting.md)
- [Queue Backend Runbook](queue-backend-runbook.md)
- [Production Deployment](production-deployment.md)
