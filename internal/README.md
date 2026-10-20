# Internal packages

A map of `internal/`. Design reasoning and known traps are in
[HANDOFF.md](../HANDOFF.md); each package's own doc comments carry the detail.

| Package | What it does |
|---|---|
| `smtp` | SMTP/ESMTP server and session: commands, DATA/BDAT spooling, AUTH, STARTTLS, relay and access control, resource and memory limits |
| `queue` | Queue manager, processor and workers; delivery handlers (SMTP, LMTP, split); per-destination shaper, MX and session caches; storage backends `file`, `sqlite`, `postgres`, `indexedfs` |
| `config` | TOML loading, defaults and validation. A field without an explicit `toml:` tag is silently ignored |
| `api` | Dashboard and HTTP API (`elemta web`): auth, roles, queue, config, campaigns, suppression |
| `auth` | Users file, API keys, sessions and RBAC for the API |
| `datasource` | SMTP AUTH backends: file, LDAP, MySQL, PostgreSQL, SQLite ([README](datasource/README.md)) |
| `plugin` | Plugin manager and built-in plugins: SPF, DKIM, DMARC, ARC, rate limiter, antivirus/antispam hooks |
| `authresult` | Inbound sender verification (SPF/DKIM/DMARC/ARC) under one deadline, and `Authentication-Results` |
| `arc` | First-party ARC (RFC 8617) verification and sealing |
| `dkim` | Outbound DKIM signing |
| `dane` | DANE for SMTP (RFC 7672): TLSA lookup and certificate matching |
| `delivery` | MTA-STS policy fetch and enforcement |
| `tlsrpt` | SMTP TLS Reporting (RFC 8460) collection and sending |
| `antivirus` | ClamAV client (INSTREAM) |
| `antispam` | Rspamd client (`/checkv2`) |
| `suppression` | Suppression list, fed by bounces and ARF feedback reports |
| `campaign` | Bulk sending (mass mailer) |
| `message` | Message type shared with plugins |
| `logging` | Console, file and Elasticsearch log sinks; per-message logging |
| `metrics` | Per-domain delivery stats, optionally in Valkey |
| `server` | TLS certificate and Let's Encrypt renewal metrics |
| `runtimepaths` | Resolves runtime file locations |
| `version` | Build version |
