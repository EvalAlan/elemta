# Logging

Every service writes JSON lines to standard output. The MTA and the admin
console also write a rotated file when they can open one; if they can't, they
say so and carry on with standard output.

## Config

```toml
[logging]
level = "info"     # debug | info | warn | error
file = "/var/log/elemta/elemta.log"
```

`type`, `output`, `format` and `options` don't send logs anywhere or change
their format. To get them to another system use log shipping.

Processes other than the MTA take their level from `LOG_LEVEL`.

## Log shipping to ELK

**Settings > Plugins > Log shipping** in the admin console sends the log of the
MTA, admin console, webmail, mailbox service and mailbox router to
Elasticsearch or Logstash. It is off until you set it up.

```
each service -> bounded queue -> capped Valkey stream -> admin console -> Elasticsearch or Logstash
```

It needs no shared log volume, no agent and no access to the Docker socket.
Each service needs `VALKEY_ADDR`, as abuse protection does. Changes apply
within about five seconds, without a restart.

### Elasticsearch

1. Open Settings, All plugins, then Log shipping's settings.
2. Enter the URL, for example `https://elasticsearch.example.com:9200`, and an
   API key or user name and password. It needs `manage_index_templates` on the
   cluster, and `create_index` and `create_doc` on `elemta-logs-*`.
3. **Send a test line**, then tick **Ship logs** and save.
4. In Kibana make a data view `elemta-logs-*` with `@timestamp` as the time.

Elemta installs an index template before the first line and writes a daily
index. It doesn't delete old ones; set a lifecycle policy.

| Field | What it is |
|---|---|
| `@timestamp`, `message`, `log.level` | the line |
| `service.name` | `mta`, `admin`, `webmail`, `mailbox` or `mailbox-router` |
| `host.name` | the process's host or container |
| `event.action` | the line's `event_type` |
| `source.ip` | the other end's address, when the line has one |
| `elemta.*` | everything else, for example `elemta.message_id : "..."` |

`elemta` is one flattened field, so lines that use one name for different types
aren't refused. Search it by exact value.

### Logstash

Use `deployments/elk/logstash-shipping.conf` as the pipeline and mount
`deployments/elk/logs-template.json` at
`/usr/share/logstash/elemta/logs-template.json`. In the console choose Logstash,
enter the input's URL (port 8080 in that file) and the user name and password
it was started with.

### What is sent

- Fields named like passwords, tokens, cookies and keys are redacted, as are
  credentials inside URLs.
- A typed SMTP command is sent only for known verbs, AUTH without its
  arguments. Command parameters and lines of a message are never sent.
- Subjects are left out unless you choose to include them.
- **Addresses and IPs are sent.** Treat the log cluster as holding personal
  data.

Redaction goes by field names and those rules. It can't know that free text in
an error message is sensitive.

### When something is down

| What | What happens |
|---|---|
| The destination | Lines wait in Valkey, up to 20,000 (80 MB at most, usually far less). Past that the oldest are dropped and counted. The console retries, and the Dashboard warns after five minutes. |
| The admin console | The same: they wait. |
| Valkey | Each service drops and counts new lines. Mail and logging carry on. |
| A service, killed | Up to its last second of lines may not be shipped. They are still on standard output. |

A batch sent again doesn't make duplicates in Elasticsearch. A line the
destination refuses outright is counted and skipped.

### The saved credential

It is in `log-shipping.json` beside the runtime configuration, mode 0600, and
is never returned by the API or sent to another host if the URL changes.
**Backups of the configuration volume contain it.**

### Filebeat instead

`make elk-up` runs a development Elasticsearch, Kibana and Filebeat. Filebeat
reads the shared log file, so it sees only the MTA and admin console. Don't
run it and log shipping into one cluster unless you want those lines twice.

## API controls

When `elemta web` is running, log level can be inspected/adjusted via API:

- `GET /api/logging/level`
- `POST /api/logging/level`
- `PUT /api/logging/level`

## Operational checks

```bash
# container logs
docker compose -f deployments/compose/docker-compose.yml logs -f elemta

# local API health + level
curl -s http://127.0.0.1:8025/api/health | jq
curl -s http://127.0.0.1:8025/api/logging/level | jq
```

## Best practices

- Use `info` for normal production operation.
- Use `debug` only during focused troubleshooting windows.
- Keep log files on writable paths with least-privilege permissions.
- Avoid logging secrets or raw credential material.
