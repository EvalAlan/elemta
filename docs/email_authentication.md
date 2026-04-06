# Email Authentication

This is the operator-facing view of email authentication in Elemta.

## Standards in scope

- SPF
- DKIM
- DMARC
- ARC

Elemta includes authentication-related plugin interfaces/implementations under `internal/plugin/`.
Runtime behavior depends on which plugins are built/loaded in your deployment.

## Minimal enablement pattern

```toml
[plugins]
directory = "/var/lib/elemta/plugins"
enabled = ["rspamd", "clamav"]
```

If you deploy additional auth plugins (`spf`, `dkim`, `dmarc`, `arc`), add them to `enabled` and ensure matching plugin binaries are present.

## DNS requirements

### SPF

Publish TXT record at root:

```text
example.com TXT "v=spf1 mx -all"
```

### DKIM

Publish selector TXT record:

```text
mail._domainkey.example.com TXT "v=DKIM1; k=rsa; p=..."
```

### DMARC

Publish policy record:

```text
_dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

### ARC

ARC is evaluated in forwarding chains and depends on participating MTAs adding/validating ARC sets.

## Practical rollout

1. Start in observe mode (log/monitor, minimal hard rejects).
2. Verify SPF/DKIM alignment for your outbound senders.
3. Move DMARC policy from `none` → `quarantine` → `reject` after confidence.
4. Track impacts in delivery logs and queue stats.

## Validation checklist

- SPF record resolves and matches sender paths.
- DKIM signatures are present and validate.
- DMARC alignment behaves as expected.
- No unexplained reject surge after policy tightening.

## Related docs

- [Plugins](plugins.md)
- [Plugin Development](plugin-development.md)
- [Logging](logging.md)
