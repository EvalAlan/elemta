# CLI Reference

Elemta currently ships three binaries:

- `elemta` — primary command (server/web/queue/cert/zimbra)
- `elemta-queue` — queue status utility
- `elemta-cli` — lightweight helper CLI (`status`, `queue`)

Build all binaries:

```bash
make build
```

---

## 1) `elemta` (primary)

```bash
./bin/elemta --help
```

Main subcommands:

- `server` — start SMTP server
- `web` — start web/API interface
- `queue` — local queue management
- `cert` — TLS/Let's Encrypt helper commands
- `zimbra` — LDAP/SOAP diagnostic commands

Global flag:

- `-c, --config <path>`

### `elemta queue` subcommands

```bash
./bin/elemta queue list
./bin/elemta queue show <message-id>
./bin/elemta queue delete <message-id>
./bin/elemta queue flush
./bin/elemta queue stats
```

### `elemta web` useful flags

```bash
./bin/elemta web --listen 127.0.0.1:8025
./bin/elemta web --queue-dir /var/spool/elemta/queue
./bin/elemta web --auth-enabled --auth-file /etc/elemta/users.txt
```

### `elemta cert` subcommands

```bash
./bin/elemta cert info
./bin/elemta cert renew
./bin/elemta cert test
```

---

## 2) `elemta-queue`

`elemta-queue` is a queue/storage status reporter. It reads config and emits queue/storage stats.

It uses `ELEMTA_CONFIG_PATH` if set.

```bash
ELEMTA_CONFIG_PATH=./config/elemta.toml ./bin/elemta-queue
```

---

## 3) `elemta-cli`

`elemta-cli` is currently minimal:

```bash
./bin/elemta-cli status
./bin/elemta-cli queue
```

If you need full queue management, use `elemta queue` or HTTP API endpoints.

---

## Docker examples

```bash
docker compose -f deployments/compose/docker-compose.yml exec elemta ./bin/elemta queue stats
```

(Adjust executable paths based on your container image layout.)
