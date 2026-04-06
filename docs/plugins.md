# Plugin System

Elemta supports plugin-driven mail processing, including built-in antispam/antivirus integrations and optional external plugin loading.

This page is an operational overview (not an internal API contract).

---

## What plugins are used for

Typical plugin-driven checks include:

- spam scoring/classification
- malware/virus scanning
- policy/rate-limit enforcement
- message annotation/rejection decisions

---

## Enabling plugins in config

```toml
[plugins]
directory = "/var/lib/elemta/plugins"
enabled = ["rspamd", "clamav"]
```

Related sections (depending on enabled plugins):

- `[antispam]`
- `[antivirus]`
- `[rate_limiter]`

---

## Built-in integrations

Common built-in integrations used in this repo:

- Rspamd (antispam)
- ClamAV (antivirus)

Behavior and thresholds are controlled by their respective config sections.

---

## External `.so` plugins

The codebase includes a plugin manager capable of loading shared-object plugins (`.so`) from a plugin directory.

Use this path carefully:

- build plugin with compatible Go/toolchain
- validate plugin path, permissions, and signatures/policies where enabled
- test in non-production first

---

## Troubleshooting plugin issues

1. Verify plugin name is listed in `[plugins].enabled`
2. Verify plugin directory exists and is readable
3. Check startup logs for plugin load/validation errors
4. Temporarily disable one plugin at a time to isolate failures

---

## Related docs

- [Configuration](configuration.md)
- [Troubleshooting](troubleshooting.md)
- [Plugin Development](plugin-development.md)
