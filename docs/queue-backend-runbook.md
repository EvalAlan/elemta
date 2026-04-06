# Queue Backend Runbook (file + sqlite)

Operator playbook for switching queue backends and validating runtime behavior.

---

## 1) Confirm active backend

### Via API

```bash
curl -s http://127.0.0.1:8025/api/queue/storage | jq
```

Look for `backend: "file"` or `backend: "sqlite"`.

### Via logs

Startup logs include backend initialization details.

---

## 2) Configure backend

```toml
[queue]
dir = "/var/spool/elemta/queue"
backend = "file" # or "sqlite"

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"
```

Rules:

- default backend is `file` when omitted
- sqlite is explicit opt-in
- no automatic migration between backends

---

## 3) Switch file -> sqlite (safe path)

1. Drain/stop SMTP traffic.
2. Stop services.
3. Set `queue.backend = "sqlite"` and sqlite settings.
4. Start services.
5. Verify with `/api/queue/storage` and logs.
6. Send a test message and confirm queue visibility.

---

## 4) Roll back sqlite -> file

1. Stop services.
2. Set `queue.backend = "file"`.
3. Start services.
4. Verify backend via logs/API.

---

## 5) Inspect sqlite queue directly

### Host-native example

```bash
sqlite3 /var/spool/elemta/queue/queue.db '.tables'
sqlite3 /var/spool/elemta/queue/queue.db "select queue_type,count(*) from queue_messages group by queue_type;"
```

### Docker example

```bash
docker compose -f deployments/compose/docker-compose.yml exec elemta \
  sqlite3 /app/queue/queue.db '.tables'
```

---

## 6) Storage sizing/health

```bash
curl -s http://127.0.0.1:8025/api/queue/storage | jq
```

Useful fields:

- `total_bytes`
- `db_bytes`, `wal_bytes`, `shm_bytes`
- `message_rows`, `content_rows`, `content_bytes`

---

## 7) SQLITE_BUSY / lock contention

Symptoms:

- transient enqueue/dequeue failures
- log messages containing `SQLITE_BUSY` or `database is locked`

Mitigation:

1. ensure one writer process owns the DB path
2. increase `busy_timeout_ms`
3. reduce concurrent queue pressure
4. if multi-writer/multi-node queue ownership is required, plan a new backend (not auto-handled in current code)

---

## 8) File backend quick checks

```bash
find /var/spool/elemta/queue -maxdepth 2 -type f | head
```

Expected:

- queue-state metadata files
- message body content under `data/`

---

## 9) Critical reminder

Changing backend changes which storage is considered authoritative.

Switching backend does **not** move existing queued messages automatically.
