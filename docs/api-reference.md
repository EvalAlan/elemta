# API Reference

This is the HTTP surface exposed by `elemta web` (`internal/api/server.go`).

## Base URL

Default local bind:

```text
http://127.0.0.1:8025
```

The JSON API lives under `/api`; login and API keys live under `/auth`.

---

## Authentication

`[api].auth_enabled` defaults to `true`, so every endpoint below except
`/api/health` and `GET /api/logging/level` needs credentials. Three ways in,
checked in this order:

- **API key:** `Authorization: Bearer <key>` (or `ApiKey <key>`)
- **HTTP Basic:** `curl -u admin ...` (same lockout rules as the login form)
- **Session cookie:** from `POST /auth/login`, as the dashboard uses

Unauthenticated API requests get `401` with a JSON body. Write requests that
rely on the cookie are refused (`403`) when `Origin`/`Referer` names another
site. Role checks apply on top: queue changes need `operator` or `admin`, user
management needs `admin`.

### `/auth`

- `POST /auth/login`
- `POST /auth/logout` (also `GET`)
- `GET /auth/me`
- `GET /auth/apikeys`, `POST /auth/apikeys`
- `GET|PUT|DELETE /auth/apikeys/{id}`
- `POST /auth/apikeys/{id}/revoke`

---

## `/api` endpoints

### Queue

- `GET /api/queue` — all queues
- `GET /api/queue/{type}` where `{type} = active|deferred|hold|failed`
- `GET /api/queue/message/{id}` — one message, with content
- `DELETE /api/queue/message/{id}`
- `POST /api/queue/message/{id}/requeue`
- `POST /api/queue/message/{id}/hold`
- `POST /api/queue/message/{id}/release-claim` — drop a stuck multi-node claim
- `POST /api/queue/{type}/retry`
- `POST /api/queue/{type}/flush` (`all` accepted)
- `GET /api/queue/stats`
- `GET /api/queue/storage` — backend and storage diagnostics
- `GET /api/queue/observability` — queue risk signals

### Messages and logs

- `GET /api/messages/search`
- `GET /api/messages/{id}/trace`
- `GET /api/logs`
- `GET /api/logs/messages`
- `GET /api/logging/level`, `POST|PUT /api/logging/level`

### Health and stats

- `GET /api/health` (no login needed)
- `GET /api/stats/delivery`
- `GET /api/stats/domains`
- `GET /api/tls/certificate`

### Suppression list

- `GET /api/suppression`
- `POST /api/suppression`
- `DELETE /api/suppression/{address}`

### Campaigns (mass mailer)

- `GET|POST /api/campaigns`
- `GET|PUT|DELETE /api/campaigns/{id}`
- `GET /api/campaigns/{id}/recipients`
- `POST /api/campaigns/{id}/{action}`
- `GET /api/directory/recipients`

### Users and roles

- `GET|POST /api/users`
- `PUT /api/users/{username}/role`
- `PUT /api/users/{username}/password`
- `DELETE /api/users/{username}`
- `GET /api/roles`
- `POST /api/account/password` — change your own password

### Config

- `GET /api/config`, `PUT /api/config`
- `GET /api/config/plugins`
- `PUT /api/config/plugins/{plugin}`
- `POST /api/config/plugins/{plugin}/check`
- `POST /api/config/restart`

---

## Non-API web routes

- `GET /` and `GET /dashboard`
- `GET /login`
- `GET /logo.png`
- `GET /static/*`
- `GET /debug/pprof/*` (behind login when auth is enabled)

---

## Example calls

```bash
# Health (public)
curl -s http://127.0.0.1:8025/api/health | jq

# Queue stats (prompts for the password)
curl -s -u admin http://127.0.0.1:8025/api/queue/stats | jq

# Delivery stats with an API key
curl -s -H "Authorization: Bearer $ELEMTA_API_KEY" \
  'http://127.0.0.1:8025/api/stats/delivery?timeScale=day' | jq

# Retry the deferred queue now
curl -s -u admin -X POST http://127.0.0.1:8025/api/queue/deferred/retry | jq
```

---

## Notes

- Response payloads are JSON for API endpoints.
- For operator workflows around queue storage backends, see [Queue Backend Runbook](queue-backend-runbook.md).
