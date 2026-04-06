# Relay Control

Relay policy is enforced during `RCPT TO` handling.

## Effective policy model

In current server behavior, a relay is accepted when one of the following is true:

1. Recipient domain is local (`local_domains`)
2. Session is authenticated
3. Client is in an allowed internal/private network class

Otherwise the server returns relay denied.

## Core config inputs

```toml
local_domains = ["example.com", "localhost"]

[auth]
enabled = true
required = false
```

## Notes

- Keep `local_domains` tight and explicit.
- Internet-facing relay without auth is a bad idea.
- For strict environments, require auth for all non-local relays and monitor rejects.

## Diagnostics

Enable normal logging and inspect relay-denied events in server logs.

```bash
docker compose -f deployments/compose/docker-compose.yml logs -f elemta
```

## Related docs

- [SMTP Server](smtp_server.md)
- [Configuration](configuration.md)
- [Troubleshooting](troubleshooting.md)
