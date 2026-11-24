# Logging

Every service writes JSON lines to standard output, and a rotated file when it
can open one; if it can't, it says so and carries on with standard output.

The admin console's Logs tab reads that file. In the Compose stacks the MTA,
the console, the webmail and the mailbox servers all write the one file on the
shared `elemta_logs` volume, so the tab shows mail flow, webmail sign-ins and
IMAP, POP3 and ManageSieve sign-ins together. Several processes can share the
file: each follows a rotation another made. A service whose `/app/logs` isn't
that volume still logs, but only to its own copy, which the tab never sees.

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

Run several consoles only with one runtime configuration volume between them,
as the HA and scale deployments do. Consoles with settings files of their own
on one Valkey would each send the lines to their own destination.

### Allow the destination first

List where logs may go in the admin console's environment, then restart it:

```
ELEMTA_LOG_SHIP_DESTINATIONS=https://elasticsearch.example.com:9200,https://logstash.example.com:8080
```

Separate them with commas. With Compose put it in the env file the
stack is started with (`.secrets/cloud.env` for the cloud deploy). With
Kubernetes set it on the admin container. The console offers only these URLs
and can't add to them, so a hijacked administrator's session can't send the
logs somewhere else. With none listed, nothing can be sent.

### Elasticsearch

1. Open Settings, All plugins, then Log shipping's settings.
2. Choose the URL and enter an
   API key or user name and password. It needs `manage_index_templates` on the
   cluster, and `create_index` and `create_doc` on `elemta-logs-*`.
3. **Send a test line**, then tick **Ship logs** and save.
4. In Kibana make a data view `elemta-logs-*` with `@timestamp` as the time.

Elemta installs an index template before the first line and writes a daily
index. It doesn't delete old ones. To have them deleted, create an ILM policy
in Elasticsearch and put its name in **Lifecycle policy**: the template then
gives it to every new daily index. For example, kept for 90 days:

```
PUT _ilm/policy/elemta-logs
{"policy": {"phases": {
  "hot":    {"actions": {}},
  "delete": {"min_age": "90d", "actions": {"delete": {}}}
}}}
```

Elemta doesn't create or change the policy, so retention stays with whoever
runs the cluster, and it writes its template again each time it starts, so a
policy added to that template by hand doesn't last. Indices made before the
policy was named keep none; give them one with
`PUT elemta-logs-*/_settings {"index.lifecycle.name": "elemta-logs"}`.

The template sets `auto_expand_replicas` to `0-1`: one replica when the
cluster has a second node, none on a single node. A replica that can never be
placed keeps the cluster yellow and holds a policy's warm phase forever, so
the delete never comes. Indices made by an older Elemta have the default of
one replica; on a single node give them
`PUT elemta-logs-*/_settings {"index.auto_expand_replicas": "0-1"}`.

| Field | What it is |
|---|---|
| `@timestamp`, `message`, `log.level` | the line |
| `service.name` | `mta`, `admin`, `webmail`, `mailbox` or `mailbox-router` |
| `host.name` | the process's host or container |
| `event.action` | the line's `event_type` |
| `source.ip` | the other end's address, when the line has one |
| `source.domain` | the other end's host name (`client_hostname`) |
| `client.ip` | who wrote the message, from its `X-Originating-IP` header (`originating_ip`, on `reception` lines), when the connecting server isn't them: the webmail with `originating_ip_header` on, or another provider that adds it. It's that system's word, not something Elemta checked |
| `user.name` | the account (`username`) |
| `event.outcome` | `success` or `failure` (`success`) |
| `event.reason` | why a sign-in failed (`failure_reason`) |
| `event.duration` | nanoseconds (`duration`) |
| `network.protocol` | `imap`, `pop3`, `webmail` and so on (`protocol`) |
| `tls.established` | whether the connection is encrypted (`tls_active`) |
| `email.message_id`, `email.local_id` | the Message-ID and the queue ID |
| `mail.size` | the message's size in bytes |
| `mail.spam_score` | rspamd's score |
| `mail.recipient_count` | how many recipients |
| `mail.response_code`, `mail.response_status` | the SMTP reply, for example `550` and `5.7.1` |
| `source.geo.*`, `source.as.*`, `client.geo.*`, `client.as.*` | where `source.ip` and `client.ip` are and whose networks they are, with the GeoIP pipeline |
| `elemta.*` | everything else, for example `elemta.auth_method : "dav"` |

`elemta` is one flattened field, so lines that use one name for different types
aren't refused. Search it by exact value. The typed fields are copies of the
key in brackets, which stays in `elemta` too; a value of another type, such as
a `size` that isn't a number, is left out of the typed field rather than
guessed at. Indices made by an older Elemta don't have the typed fields: new
lines get them from the next daily index.

### GeoIP and network owners

Elasticsearch can add where an address is and which network it belongs to, from
its free GeoLite2 City and ASN databases. It downloads them when a pipeline
first uses them and keeps them up to date, so the cluster needs to reach
`geoip.elastic.co`.

1. Create the pipeline from `deployments/elk/geoip-pipeline.json`:
   `PUT _ingest/pipeline/elemta-geoip` with the file as the body.
2. Put `elemta-geoip` in **Ingest pipeline** in Log shipping's settings, save
   and **Send a test line**. While the named pipeline doesn't exist,
   Elasticsearch refuses every line, and the test says so.
3. In Kibana, `source.geo.location` draws on a map, and `source.as.number` and
   `source.as.organization.name` show whose networks the traffic comes from.

Every processor in the file ignores failure, so an address it can't place, or
a database that hasn't downloaded yet, leaves the line without those fields
rather than refused. The credential needs no more privileges for this: the
index's default pipeline runs whoever writes. Private and loopback addresses
have no location.

### Logstash

Use `deployments/elk/logstash-shipping.conf` as the pipeline and mount
`deployments/elk/logs-template.json` at
`/usr/share/logstash/elemta/logs-template.json`. In the console choose Logstash,
choose the input's URL (port 8080 in that file, and it has to be listed as
above) and enter the user name and password it was started with.
Logstash installs the template from that file, so the console's lifecycle
policy doesn't apply; add `"settings": {"index.lifecycle.name": "..."}` under
`template` in the file instead.

### Where it can send

Only the URLs in `ELEMTA_LOG_SHIP_DESTINATIONS`, matched whole: scheme, host,
port and path. They can be on private networks or loopback, since that is
where log clusters are. Removing one and restarting stops shipping to it; the
Dashboard warns and lines wait. Even for a listed URL, link-local, cloud metadata, multicast
and unspecified addresses are refused on every connection, redirects aren't
followed, and proxy settings from the environment aren't used.

### What is sent

The same redaction as the local log (see "What the log holds" below), and
subjects are left out unless you choose to include them.

- Fields named like passwords, tokens, cookies and keys are redacted, as are
  credentials inside URLs.
- A typed SMTP command is sent only for known verbs, AUTH without its
  arguments. Command parameters and lines of a message are never sent.
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

## What the log holds

Every Elemta process redacts its log before writing it, to stdout and to the
log file alike, whatever the line:

- Fields named like passwords, tokens, cookies and keys show `[redacted]`.
  A yes/no field such as `has_password` stays.
- A user and password inside a URL, such as a Valkey or database address,
  become `[redacted]@`, in any field, in the message and in errors.
- A client's command is kept only when SMTP or LMTP knows its verb, and AUTH
  never keeps its arguments. Anything else a client types shows
  `[redacted]`: after a refused AUTH, a mail app often sends the password
  next, as what looks like an unknown command.
- Lines of a message and other raw client input (`line`, `args`,
  `parameters`, `sanitized_input`) show `[redacted]`.

Subjects, addresses and IPs stay in the local log. Log shipping leaves
subjects out too unless you include them.

## Best practices

- Use `info` for normal production operation.
- Use `debug` only during focused troubleshooting windows.
- Keep log files on writable paths with least-privilege permissions.
- Avoid logging secrets or raw credential material.
