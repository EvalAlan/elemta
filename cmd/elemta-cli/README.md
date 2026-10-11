# elemta-cli

`elemta-cli` is a queue client for a running `elemta web`, over its HTTP API.

## Build

```bash
make build   # produces bin/elemta-cli
```

## Commands

`status`, `version`, and `queue list|show|delete|retry|flush|stats`. Pass
`--api-url` (the default, `http://localhost:8081`, is not the dashboard's
port) and `--api-key`. See [docs/cli.md](../../docs/cli.md#3-elemta-cli) for
examples.
