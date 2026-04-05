# Queue Backend Runbook (file + sqlite)

This is the operator playbook for switching backends, validating runtime behavior, and troubleshooting queue storage.

## 1) Confirm active backend

Check logs on startup:

- `queue_backend=...`
- `Initializing unified queue system ... backend=...`
- For sqlite: `SQLite queue backend initialized`

Or query API:

```bash
curl -s http://localhost:8025/api/queue/storage | jq
```

Look for `backend: "file"` or `backend: "sqlite"`.

## 2) Configure backend

```toml
[queue]
dir = "/app/queue"
backend = "file" # or "sqlite"

[queue.sqlite]
path = "/app/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"
```

Rules:

- default is `file` when `queue.backend` is omitted
- sqlite is opt-in only
- no automatic migration between backends

## 3) Switch file -> sqlite safely

1. Stop traffic or drain deliveries.
2. Stop services.
3. Set `queue.backend = "sqlite"` and sqlite settings.
4. Start services.
5. Verify with `/api/queue/storage` and logs.
6. Send a test message and verify queue visibility.

## 4) Switch sqlite -> file rollback

1. Stop services.
2. Set `queue.backend = "file"`.
3. Start services.
4. Verify logs and `/api/queue/storage` report `backend=file`.

## 5) Inspect sqlite queue directly

From container:

```bash
docker compose -f deployments/compose/docker-compose.yml exec elemta \
  sqlite3 /app/queue/queue.db '.tables'

# Queue counts by state
docker compose -f deployments/compose/docker-compose.yml exec elemta \
  sqlite3 /app/queue/queue.db "select queue_type,count(*) from queue_messages group by queue_type;"
```

## 6) Storage sizing and health

API endpoint:

```bash
curl -s http://localhost:8025/api/queue/storage | jq
```

Key fields:

- `total_bytes`, `db_bytes`, `wal_bytes`, `shm_bytes`
- `message_rows`, `content_rows`, `content_bytes`
- sqlite page stats (`page_size`, `page_count`, `freelist_count`)

## 7) SQLITE_BUSY / lock contention

Symptoms:

- transient enqueue failures
- log errors containing `SQLITE_BUSY` / `database is locked`

Current mitigation in code:

- sqlite backend uses single shared DB connection
- `busy_timeout` configured (default 5000ms)
- WAL mode enabled by default

If this still appears under load:

1. confirm only one queue writer process owns queue DB
2. increase `busy_timeout_ms`
3. reduce enqueue/delivery concurrency
4. if multi-writer requirements grow, plan Postgres backend

## 8) File backend quick checks

```bash
find /app/queue -maxdepth 2 -type f | head
```

- metadata files are `.json`
- message content lives under `/app/queue/data`

## 9) No-auto-migration reminder

Changing backend changes where queue state is read from.

- switching backend does **not** move queued messages automatically
- migration should be explicit and operator-driven
