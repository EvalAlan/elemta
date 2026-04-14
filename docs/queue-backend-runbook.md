# Queue Backend Runbook (file + sqlite + postgres)

Operator playbook for switching queue backends, validating runtime behavior, and running Postgres in multi-node/failover scenarios.

---

## 1) Confirm active backend

### Via API

```bash
curl -s http://127.0.0.1:8025/api/queue/storage | jq
```

Look for `backend: "file"`, `"sqlite"`, or `"postgres"`.

### Via config

```bash
grep -nE '^\[queue\]|^backend|^\[queue\.sqlite\]|^\[queue\.postgres\]|^dsn' config/elemta.toml
```

### Via logs

Startup logs include queue initialization and storage backend details.

---

## 2) Configure backend

```toml
[queue]
dir = "/var/spool/elemta/queue"
backend = "file" # file | sqlite | postgres

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"

[queue.postgres]
dsn = "postgres://elemta:secret@db-host:5432/elemta_queue?sslmode=disable"
max_open_conns = 20
max_idle_conns = 10
conn_max_lifetime_seconds = 1800
```

Rules:

- default backend is `file` when omitted
- sqlite/postgres are explicit opt-in
- no automatic migration between backends

---

## 3) Local dev quick-start (postgres)

One-command path:

```bash
make install-dev-postgres
```

This target:

1. boots dev stack
2. starts `elemta-postgres` on the detected compose network
3. waits for Postgres readiness
4. configures `backend = "postgres"`
5. restarts `elemta` + `elemta-web`

---

## 4) Switch backends safely

### file/sqlite -> postgres

1. Drain/stop SMTP traffic.
2. Stop services.
3. Set `queue.backend = "postgres"` and valid `[queue.postgres]` DSN.
4. Start services.
5. Verify via API/logs.
6. Send test message and verify queue rows in Postgres.

### postgres -> file/sqlite rollback

1. Stop services.
2. Set target backend.
3. Start services.
4. Verify backend via API/logs.

---

## 5) Postgres schema and multi-node semantics

Current Postgres queue schema includes claim columns:

- `claimed_by TEXT`
- `claim_until TIMESTAMPTZ`

Workers use atomic claim/lease semantics (`FOR UPDATE SKIP LOCKED`) to avoid double-processing under multi-node concurrency.

Operational meaning:

- each message is claimed by one worker at a time
- if a worker dies, claim lease expires and another worker can claim it
- queue moves reset claim state (`claimed_by`, `claim_until`)

---

## 6) Validate postgres queue activity

```bash
docker exec -it elemta-postgres psql -U elemta -d elemta_queue -c \
"select queue_type, count(*) from queue_messages group by 1 order by 1;"
```

Inspect claim state:

```bash
docker exec -it elemta-postgres psql -U elemta -d elemta_queue -c \
"select id, queue_type, claimed_by, claim_until, created_at from queue_messages order by created_at desc limit 20;"
```

Inspect message metadata fields stored in JSON:

```bash
docker exec -it elemta-postgres psql -U elemta -d elemta_queue -c \
"select id, metadata->>'retry_count' as retry_count, metadata->>'last_error' as last_error from queue_messages order by created_at desc limit 20;"
```

---

## 7) Datacenter failover guidance

Postgres backend helps failover, but only with HA database topology.

Recommended baseline:

- HA Postgres endpoint (managed PG, Patroni, etc.)
- streaming replication + automatic failover
- WAL archiving + PITR backups
- same DSN endpoint for all Elemta nodes

Behavior during failover:

- brief DB outage can produce SMTP 451 tempfails
- senders retry per SMTP norms
- once DB endpoint recovers/fails over, queue processing resumes

Design note:

- with claim/lease semantics in place, multi-node processors are safe to run in active-active mode against shared Postgres queue state

---

## 8) Troubleshooting postgres backend

### `lookup ... no such host`

- DSN host is wrong or not resolvable inside container network
- validate runtime config loaded by container (`/tmp/elemta-web.toml`)
- ensure Postgres container/service is on same Docker network

### SMTP `451 4.3.0 Message processing failed`

- check `elemta` logs for enqueue/storage errors
- verify Postgres connectivity and schema

### Empty queue table during tests

- if delivery is fast, queue can drain immediately
- force a temporary delivery failure (stop LMTP target) to observe queued rows

---

## 9) Critical reminder

Changing backend changes which storage is authoritative.

Switching backend does **not** move existing queued messages automatically.
