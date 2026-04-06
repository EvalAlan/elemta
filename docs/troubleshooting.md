# Troubleshooting

Focused checks for the current Elemta repo/runtime.

---

## 1) Service won't start

### Check config path and parseability

```bash
./bin/elemta server --config ./config/elemta.toml
```

If no config is found, Elemta falls back to defaults and logs that behavior.

### Port already in use

```bash
ss -tlnp | grep -E ':25|:2525|:8025|:8080'
```

Then either free the port or override settings in config/flags.

---

## 2) Docker stack issues

```bash
make status
make logs
make logs-elemta
```

Compose file in use:

- `deployments/compose/docker-compose.yml`

Hard reset when needed:

```bash
make down
make rebuild
```

---

## 3) Queue not draining

```bash
# Local queue view
./bin/elemta queue stats
./bin/elemta queue list

# API view
curl -s http://127.0.0.1:8025/api/queue/stats | jq
curl -s http://127.0.0.1:8025/api/queue/storage | jq
```

If using sqlite backend, confirm `[queue].backend = "sqlite"` and sqlite path is writable.

---

## 4) Auth failures

Validate auth section in TOML:

```toml
[auth]
enabled = true
required = true
datasource_type = "file" # or ldap/mysql/postgres/sqlite
```

Common breakage:

- wrong datasource path/host/credentials
- `auth_file` path points to a directory for web auth

---

## 5) TLS / STARTTLS problems

Check cert/key readability and paths:

```bash
openssl x509 -in /path/to/cert.pem -text -noout
```

Confirm config:

```toml
[tls]
enabled = true
enable_starttls = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
```

---

## 6) API/web unreachable

Default listen is `127.0.0.1:8025`.

```bash
curl -i http://127.0.0.1:8025/api/health
```

If bound to loopback, remote hosts cannot reach it unless proxied or reconfigured.

---

## 7) Log file permission warnings

If you see permission errors opening `/var/log/elemta/elemta.log`, either:

- run with correct privileges, or
- point logging to a writable file/path in config.

---

## 8) Minimal sanity command set

```bash
make test
make lint
make status
curl -s http://127.0.0.1:8025/api/health | jq
```
