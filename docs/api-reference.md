# API Reference

This is the current HTTP API surface exposed by `elemta web`.

## Base URL

Default local bind:

```text
http://127.0.0.1:8025
```

API namespace:

```text
/api
```

---

## Core endpoints

### Queue

- `GET /api/queue`
- `GET /api/queue/{type}` where `{type} = active|deferred|hold|failed`
- `GET /api/queue/message/{id}`
- `DELETE /api/queue/message/{id}`
- `POST /api/queue/{type}/flush` (`all` accepted for flush)
- `GET /api/queue/stats`
- `GET /api/queue/storage`

### Health and stats

- `GET /api/health`
- `GET /api/stats/delivery`

### Logs

- `GET /api/logs`
- `GET /api/logs/messages`
- `GET /api/logging/level`
- `POST /api/logging/level`
- `PUT /api/logging/level`

### Config

- `GET /api/config`
- `PUT /api/config`
- `GET /api/config/plugins`
- `PUT /api/config/plugins/{plugin}`
- `POST /api/config/restart`

### Utility


---

## Auth-related endpoints (when auth is enabled)

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

API key management:

- `GET /api/keys`
- `POST /api/keys`
- `GET /api/keys/{id}`
- `PUT /api/keys/{id}`
- `DELETE /api/keys/{id}`
- `POST /api/keys/{id}/revoke`

---

## Non-API web routes

- `GET /` and `GET /dashboard`
- `GET /login`
- `GET /logo.png`
- `GET /debug/pprof/*` (availability depends on auth setup)

---

## Example calls

```bash
# Queue stats
curl -s http://127.0.0.1:8025/api/queue/stats | jq

# Delivery stats
curl -s 'http://127.0.0.1:8025/api/stats/delivery?timeScale=day' | jq

# Flush deferred queue
curl -s -X POST http://127.0.0.1:8025/api/queue/deferred/flush | jq
```

---

## Notes

- Response payloads are JSON for API endpoints.
- Auth/authorization behavior depends on `[api].auth_enabled` and related auth settings.
- For operator workflows around queue storage backends, see [Queue Backend Runbook](queue-backend-runbook.md).
