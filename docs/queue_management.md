# Queue Management

Elemta supports `file` (default), `sqlite`, `postgres` and `indexedfs` queue storage with the same queue lifecycle semantics.

---

## Queue states

Current queue states:

- `active` — ready for processing
- `deferred` — temporarily failed, scheduled for retry
- `hold` — manually/admin held
- `failed` — exhausted retry policy or hard-failed

---

## Backend selection

```toml
[queue]
dir = "/var/spool/elemta/queue"
backend = "file" # file | sqlite | postgres | indexedfs

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"
```

Rules:

- Default backend is `file` when unset.
- `sqlite`, `postgres` and `indexedfs` are explicit opt-in. Postgres is the multi-node backend.
- Switching backend does **not** auto-migrate existing queued mail.

See: [Queue Backend Runbook](queue-backend-runbook.md).

---

## Queue processor

```toml
[queue_processor]
enabled = true
interval = 10
workers = 20
debug = false
```

The queue processor runs delivery attempts and transitions messages between states.

---

## CLI operations

Use `elemta queue` for local queue management:

```bash
./bin/elemta queue list
./bin/elemta queue show <message-id>
./bin/elemta queue delete <message-id>
./bin/elemta queue flush
./bin/elemta queue stats
```

---

## HTTP API operations

Base API path: `/api`

- `GET /api/queue` — all messages
- `GET /api/queue/{type}` — specific queue (`active|deferred|hold|failed`)
- `GET /api/queue/message/{id}` — one message (+ content)
- `GET /api/queue/stats` — queue counters
- `GET /api/queue/storage` — backend/storage diagnostics
- `DELETE /api/queue/message/{id}` — delete one message
- `POST /api/queue/{type}/flush` — flush a queue (`all` supported)
- `POST /api/queue/{type}/retry` — retry a queue now
- `POST /api/queue/message/{id}/requeue`, `/hold`, `/release-claim`

All of these need a login; see [API Reference](api-reference.md#authentication).

---

## File backend layout (default)

The file backend stores:

- queue metadata per state directory
- message content under `data/`

All queue files are written with secure permissions and atomic update semantics.

---

## Operational checks

```bash
# API queue stats
curl -s -u admin http://127.0.0.1:8025/api/queue/stats | jq

# Storage/backend diagnostics
curl -s -u admin http://127.0.0.1:8025/api/queue/storage | jq
```

---

## Related docs

- [Queue Backend Runbook](queue-backend-runbook.md)
- [API Reference](api-reference.md)
- [Troubleshooting](troubleshooting.md)
