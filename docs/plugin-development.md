# Plugin Development

This page documents the **current** plugin loading contract at a practical level.

## Stability note

Plugin interfaces are internal and evolving. Treat this as implementation guidance, not a long-term ABI guarantee.

## Loader expectations (today)

The plugin manager loads `.so` files from the configured plugin directory and expects:

- exported `PluginInfo` symbol (`*plugin.PluginInfo`)
- type-specific constructor/symbols based on `PluginInfo.Type`

Examples from current loader behavior:

- `antivirus` / `antispam` / generic types: exported `Plugin` symbol
- `dkim`: exported `NewDKIMPlugin() DKIMPlugin`
- `spf`: exported `NewSPFPlugin() SPFPlugin`
- `dmarc`: exported `NewDMARCPlugin() DMARCPlugin`
- `arc`: exported `NewARCPlugin() ARCPlugin`
- `ratelimit`: exported `NewRateLimiterPlugin() RateLimitPlugin`

## Enable plugins

```toml
[plugins]
directory = "/var/lib/elemta/plugins"
enabled = ["myplugin"]
```

At runtime, loader resolves `myplugin` to:

- `/var/lib/elemta/plugins/myplugin.so`

## Build pattern

```bash
go build -buildmode=plugin -o myplugin.so ./path/to/plugin
```

Place the resulting `.so` in your configured plugin directory.

## Operational advice

- Validate plugin loading in a non-production environment first.
- Keep plugin changes and server upgrades tightly versioned together.
- Treat plugin panics/load failures as deploy blockers until explained.

## Source references

- `internal/plugin/manager.go`
- `internal/plugin/types.go`
- `internal/plugin/*.go` (type-specific interfaces)
