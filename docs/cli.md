# CLI Reference

Elemta currently ships three binaries:

- `elemta` — primary command (server/web/queue/cert/zimbra)
- `elemta-queue` — queue status utility
- `elemta-cli` — remote queue client over the HTTP API

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
- `user` — dashboard/API accounts (also editable in Settings > Users)
- `dkim` — generate DKIM keys, print their DNS records, check DNS before a rotation
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

### Reloading configuration

There is no reload subcommand. A running `elemta server` reloads on `SIGHUP`
(`docker kill -s HUP <container>`), and also notices within about 5 seconds
when its configuration file changes, which is how dashboard edits apply.

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

### `elemta user` subcommands

Changes apply to a running server on its next request; no restart.

```bash
./bin/elemta user add alice --role operator --file /etc/elemta/users.txt
./bin/elemta user role alice admin --file /etc/elemta/users.txt
./bin/elemta user role bob domain-admin --domains example.com --file /etc/elemta/users.txt
./bin/elemta user passwd alice --file /etc/elemta/users.txt
./bin/elemta user list --file /etc/elemta/users.txt
./bin/elemta user remove alice --file /etc/elemta/users.txt
```

Roles: `admin`, `operator` (queue management), `user` and `readonly` (view only),
and `domain-admin` (mail administration of the `--domains` given; see
[mail administration](mail-administration.md#domain-administrators)).

### `elemta dkim` subcommands

See [DKIM signing](dkim-signing.md#rotating-a-key) for the rotation order.

```bash
./bin/elemta dkim keygen --domain example.com --selector s2026b --out /etc/elemta/dkim/s2026b.key
./bin/elemta dkim record --domain example.com --selector s2026b --key /etc/elemta/dkim/s2026b.key
./bin/elemta dkim check  --domain example.com --selector s2026b --key /etc/elemta/dkim/s2026b.key
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

`elemta-cli` drives a running `elemta web` over its HTTP API, so it works from
any host that can reach the dashboard. Its `--api-url` default is
`http://localhost:8081`, not the dashboard's `8025`, so pass it explicitly:

```bash
export API="--api-url http://127.0.0.1:8025 --api-key $ELEMTA_API_KEY"

./bin/elemta-cli $API status
./bin/elemta-cli $API queue list [active|deferred|hold|failed]
./bin/elemta-cli $API queue show <message-id> [--raw]
./bin/elemta-cli $API queue delete <message-id>
./bin/elemta-cli $API queue retry [queue-type]
./bin/elemta-cli $API queue flush [queue-type] --yes   # deletes messages
./bin/elemta-cli $API queue stats
./bin/elemta-cli version
```

Create the API key in the dashboard or with `POST /auth/apikeys`; see the
[API Reference](api-reference.md#authentication).

---

## Docker examples

```bash
docker compose -f deployments/compose/docker-compose.yml exec elemta ./bin/elemta queue stats
```

(Adjust executable paths based on your container image layout.)
