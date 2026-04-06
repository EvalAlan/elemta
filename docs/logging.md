# Logging

This page covers current logging behavior and controls.

## Runtime behavior

Elemta initializes logging very early.

Typical behavior:

- logs to stdout
- tries to open configured log file
- if file open fails, continues with stdout and emits a warning

Example warning seen during local runs:

```text
failed to open log file ... permission denied
```

## Config

```toml
[logging]
type = "console"   # console | file | elastic
level = "info"     # debug | info | warn | error
format = "text"    # text | json
file = "/var/log/elemta/elemta.log"
output = ""
```

Notes:

- `file` is used for file output path.
- `output` is used by non-file sinks (e.g. elastic URL).
- `options` can carry sink-specific extras.

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
