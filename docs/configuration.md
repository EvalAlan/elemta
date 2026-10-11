# Elemta Configuration

Elemta runtime configuration is loaded from **TOML**.

> `.conf` filenames are still searched for compatibility, but the parser expects TOML content.

---

## Config file discovery order

When `--config` is not provided, Elemta searches common paths in order:

1. `./elemta.toml`
2. `./elemta.conf`
3. `./config/elemta.toml`
4. `./config/elemta.conf`
5. `../config/elemta.toml`
6. `../config/elemta.conf`
7. `$HOME/.config/elemta/elemta.toml`
8. `$HOME/.elemta.toml`
9. `$HOME/.elemta.conf`
10. `/etc/elemta/elemta.toml`
11. `/etc/elemta/elemta.conf`

You can always pin a file explicitly:

```bash
./bin/elemta server --config ./config/elemta.toml
```

---

## Minimal working config

```toml
hostname = "mail.example.com"
listen_addr = ":2525"
max_size = 52428800
local_domains = ["example.com", "localhost"]

[queue]
dir = "/var/spool/elemta/queue"
backend = "file" # file | sqlite | postgres | indexedfs

[queue.sqlite]
path = "/var/spool/elemta/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"

[queue.postgres]
dsn = "postgres://elemta:secret@127.0.0.1:5432/elemta_queue?sslmode=disable"
max_open_conns = 20
max_idle_conns = 10
conn_max_lifetime_seconds = 1800

[auth]
enabled = false
required = false
allow_deprecated_sha1 = true # migration switch for legacy {SHA}/{SSHA}
datasource_type = "file"
datasource_path = "/etc/elemta/users.txt"

[delivery]
mode = "lmtp"
host = "127.0.0.1"
port = 2424
timeout = 30
max_retries = 3
retry_delay = 60

[metrics]
enabled = true
listen_addr = ":8080"

[api]
enabled = true
listen_addr = "127.0.0.1:8025"
web_root = "./web/static"
auth_enabled = true
auth_file = "/etc/elemta/users.txt"

[queue_processor]
enabled = true
interval = 10
workers = 5
debug = false

[logging]
type = "console"
level = "info"
format = "text"
file = "/var/log/elemta/elemta.log"
```

---

## Key sections used in current code

### Top-level SMTP/runtime fields

- `hostname`
- `listen_addr`
- `[server].listen_submission` — optional submission port (RFC 6409, usually
  `:587`); `MAIL FROM` there needs a login or an `allowed_relays` network
- `max_size`
- `local_domains`
- `allowed_relays` — IPs, CIDRs, or the names `"private"` / `"loopback"`,
  that may relay to non-local domains without authenticating. Loopback always may; nothing else is implied (private ranges
  were before v0.3, which made the server an open relay behind SNAT, a load
  balancer or Docker's userland proxy). `dev_mode` no longer bypasses this.
- `failed_queue_retention_hours`
- `max_workers`, `max_retries`, `max_queue_time`, `retry_schedule`
- `max_connections_per_domain` — simultaneous outbound deliveries to one
  destination domain (the per-destination traffic shaper). Keep it at or above
  `[queue_processor].workers` for single-domain benchmarks, or the number
  measures the shaper
- `session_timeout` (duration string, e.g. `5m`)
- `strict_line_endings` (default `true`)
- `trusted_networks` (CIDRs; default loopback + RFC 1918)
- `spool_threshold_bytes` (default 262144)

### Trusted networks

`trusted_networks` is a list of CIDRs whose peers are treated as internal.
Internal peers take a permissive content-validation path; everyone else gets
the full checks.

Unset, it defaults to loopback and the RFC 1918 ranges the server has always
treated as internal:

```
127.0.0.0/8    ::1/128    10.0.0.0/8    172.16.0.0/12
```

Note what is *not* in that list. `192.168.0.0/16`, link-local and IPv6 ULA are
private addresses, but they are not trusted by default, because trusting them
would grant more than earlier releases did. Add them explicitly if your
deployment needs them:

```toml
trusted_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

Setting it to an empty list trusts nothing, so every connection takes the
external path. That is how the test suite reaches that path while connecting
over loopback.

A malformed entry fails at startup rather than being dropped: silently
discarding one narrows trust and starts refusing mail from a network you meant
to allow, while silently falling back to the defaults widens it.

> Earlier releases matched the peer address by string prefix. That treated
> `172.0.0.0/8` as private when only `172.16.0.0/12` is, and matched any IPv6
> address *containing* `::1` — which includes routable addresses such as
> `2001:db8::1`, since `::1` is a conventional first host address in a subnet.
> Both granted the permissive path to peers that should not have had it.
> Matching is now done on the parsed address.

### RFC 5321 line endings

`strict_line_endings` enforces CRLF termination inside `DATA`. It defaults to
`true` and is the primary defence against SMTP smuggling: a bare LF that this
server treats as ordinary message content may be interpreted as a line
terminator by a downstream server, which lets an attacker split one submission
into several messages and forge the envelope of the extra ones.

With it enabled, a bare CR or bare LF in `DATA` is rejected with
`500 5.5.2`, and `.\n` is not honoured as an end-of-data marker.

Set it to `false` only to interoperate with legacy senders that emit bare LF,
and only if you understand that this re-opens the vector.

> Prior to this being wired through, the value was always `false` in shipped
> binaries regardless of configuration, because the field was never mapped
> into the SMTP server's config. Deployments upgrading from an older build
> will see strict enforcement turn on for the first time; if that rejects
> mail you need to accept, set `strict_line_endings = false` explicitly.

### Access control (allow / deny lists)

`[access_control]` refuses connections and senders outright. It is distinct
from `trusted_networks`, which only decides how strictly a peer's *content* is
validated — this decides whether the peer may talk to the server at all.

```toml
[access_control]
enabled = true
allow_ips     = ["10.1.2.3"]
deny_ips      = ["203.0.113.0/24"]
allow_domains = ["newsletter.partner.example"]
deny_domains  = ["spam.example"]
```

- **Allow beats deny.** A host in both lists is allowed, so a known-good server
  inside a denied range can be permitted without restating the range.
- **Addresses** may be CIDR ranges or single hosts. Denied peers are refused
  with `554` before the greeting, so a blocked address costs one round trip and
  no session state.
- **Domains** are matched against the `MAIL FROM` domain *and its subdomains*,
  so `spam.example` also covers `mail.spam.example`. Matching stops before a
  bare TLD, so an entry of `com` cannot refuse everything.
- **The empty sender (`<>`) is never refused.** That is the bounce path, and
  blocking it would break delivery status notifications.
- A malformed entry stops the server at startup rather than being skipped: a
  deny rule that silently fails to load leaves you believing a network is
  blocked when it is not.

Disabled by default. Changes are read at startup, so they take effect after a
restart.

### Queue backend

- `[queue].dir`
- `[queue].backend` (`file`, `sqlite`, `postgres`, or `indexedfs`)
- `[queue.sqlite]` settings
- `[queue.indexedfs]` settings (`index_path`, `content_dir`, `sync_mode`, `recovery_on_startup`)
- `[queue.postgres]` settings (`dsn`, pool sizing)

### API/web

- `[api].enabled`
- `[api].listen_addr`
- `[api].web_root`
- `[api].auth_enabled`
- `[api].auth_file`

> Use `elemta user add --file <path>` to create the users file; see the
> hardening section of [Production Deployment](production-deployment.md).
>
> **Security:** `auth_enabled` defaults to `true` (since v0.2.0): a config
> that does not mention it requires a login. The admin API can read queued
> mail, flush queues, and rewrite configuration, so turning auth off is only
> safe on loopback; the server logs a `SECURITY:` warning at startup if it is
> off on any other address. See the hardening section of
> [Production Deployment](production-deployment.md).

### Auth

- `[auth].enabled`
- `[auth].required`
- `[auth].allow_deprecated_sha1` (default true; set false to block legacy `{SHA}`/`{SSHA}` password verification)
- `[auth].allow_plaintext_auth` (default false). AUTH PLAIN/LOGIN is only
  offered and accepted after STARTTLS, or from loopback; set true to allow it
  in the clear from anywhere, which exposes passwords to anyone on the path.
- `[auth].allow_any_sender` (default false). An authenticated client may
  only use a MAIL FROM it owns, or gets `553 5.7.1`. A login that is an
  address owns that address; a bare login (`alice`) owns `alice@` at every
  `local_domains` entry; the null sender `<>` is always allowed. Clients on
  `allowed_relays` that did not authenticate are not checked.
- `[auth.sender_aliases]` grants a login extra senders, as addresses or whole
  domains:

  ```toml
  [auth.sender_aliases]
  "alice@example.com" = ["sales@example.com", "@example.org"]
  ```
- Failed AUTH attempts are counted per client address across connections
  (10 per 15 minutes, then `421`), so reconnecting does not reset the limit.
- datasource fields (`datasource_type`, `datasource_path`, `datasource_host`, etc.)

### Delivery

- `[delivery].mode`
- `[delivery].host`
- `[delivery].port`
- `[delivery].max_messages_per_minute_per_domain` (default 0, no limit) caps
  the send rate to one destination. A destination that defers is backed off
  on its own, with a doubling interval, without blocking a worker.
- `[delivery].verify_recipients` — ask the LMTP server at RCPT time whether a
  local mailbox exists and refuse unknown users with `550 5.1.1`, instead of
  accepting and bouncing (backscatter). Default on in `lmtp`/`split` mode when
  `[delivery].host` is set. If the mailbox server cannot answer, recipients
  are accepted unverified and probing pauses for 30 seconds.
- `[delivery].reuse_connections` (default true). After an outbound delivery
  the SMTP session is kept open for up to 5 seconds and the next message to
  the same MX address goes over it, skipping connect, EHLO and the TLS
  handshake. A session carries at most 100 messages and lives at most 5
  minutes; at most 4 are parked per MX address and 256 in total. Set false
  to open a new connection for every message.
- `[delivery].dane` (default false) and `[delivery].dane_resolver` (default
  `127.0.0.1:53`). DANE for SMTP (RFC 7672): when a recipient domain's MX
  records are DNSSEC-signed and the MX host publishes signed TLSA records at
  `_25._tcp.<mx>`, the host's certificate must match one of them (DANE-EE or
  DANE-TA; PKIX usages are ignored, as the RFC says). A mismatch, or a host
  that stops offering STARTTLS, is refused with no fallback, and the next MX
  is tried. DANE takes precedence over MTA-STS where both apply. Needs a
  DNSSEC-validating resolver (unbound, systemd-resolved, BIND) whose AD bit
  is trusted, so keep it on loopback; the server warns at startup otherwise.
  A DNSSEC lookup that fails defers the message rather than sending without
  DANE, so a resolver outage holds outbound mail.
- retry/timeouts

### Sending IP pools

`[[delivery.pools]]` defines named sets of source addresses (virtual MTAs)
for remote SMTP delivery, so separate mail streams build separate sending
reputations. Pools need a restart to change.

```toml
[delivery]
mode = "smtp"
default_pool = "transactional"

[[delivery.pools]]
name = "transactional"
senders = ["example.com", "alerts@corp.example"]

[[delivery.pools.ips]]
address = "203.0.113.10"
helo = "mta1.example.com"

[[delivery.pools]]
name = "bulk"
senders = ["news.example.com", ".promo.example.com"]
warmup_schedule = [200, 500, 1000, 2000, 5000, 10000, 20000, 50000]

[[delivery.pools.ips]]
address = "203.0.113.20"
helo = "bulk1.example.com"
warmup_start = "2026-10-01"

[[delivery.pools.ips]]
address = "203.0.113.21"
helo = "bulk2.example.com"
```

- **Selection.** A message goes to the pool whose `senders` match its
  envelope sender: a full address beats a domain, which beats a
  leading-dot entry (`.promo.example.com` covers every subdomain, not the
  domain itself). A sender no pool claims, including the null sender of a
  bounce, goes to `default_pool`; with no `default_pool` it leaves unpooled,
  from whatever address the kernel picks, as before. A sender may be claimed
  by only one pool, and an address may be in only one pool.
- **Addresses.** Deliveries rotate across a pool's `ips`. Each connection
  binds to the address and sends `helo` in EHLO (default: the server
  hostname); set `helo` to the address's PTR name, with forward DNS that
  points back. An IPv4 address only reaches IPv4 MX addresses and an IPv6
  address only IPv6 ones. Every address must be bindable on the host, or
  startup is refused: a missing address would otherwise fail every
  connection and look like the destination refusing mail.
- **Warmup.** An address with a `warmup_start` (UTC date) is capped at
  `warmup_schedule[n]` messages on the n-th day after it, counting each SMTP
  transaction (one message to one recipient domain) that reached the
  receiver. Past the end of the schedule the address is uncapped. The cap
  is released evenly over the UTC day, plus one hour's worth up front, so a
  warming address never sends its whole day in a burst; the rest of the
  traffic goes to the pool's other addresses. When every address in a pool
  is at its cap, mail defers and is retried on the normal schedule. That
  deferral is not treated as the destination deferring, so it does not back
  off the destination. Counts are saved to `[delivery] pool_state_file`
  (default `pool-state.json` in the queue directory) every 10 seconds and at
  shutdown.
- **Shaping.** With pools, `max_connections_per_domain`,
  `max_messages_per_minute_per_domain` and deferral backoff apply per
  source address per destination, because receivers throttle by sending IP.
  Parked outbound sessions are also kept per source address, so mail never
  leaves through another pool's connection.

### Mailbox provider profiles

Gmail, Yahoo (which also hosts AOL) and Microsoft (Outlook.com and
Microsoft 365) apply their limits per sending IP across every domain they
host. `[delivery] provider_profiles` is on by default; set it to false to
go back to plain per-domain shaping. While it is on:

- **Matching by MX.** A recipient domain whose most preferred MX host ends
  in a provider's suffix (`google.com`, `googlemail.com`; `yahoodns.net`;
  `protection.outlook.com`) is shaped as that provider. gmail.com and every
  Google Workspace domain then share one connection cap, rate cap and
  backoff per source address. A provider that appears only as a backup MX
  does not count.
- **Throttle replies.** A deferral whose text is the provider's own "you
  are being limited" reply counts as a throttle. For Google that is
  `4.7.28`. For Yahoo it is `[TSS04]` or `[TSS09]`. For Microsoft it is
  `4.7.650`, `RP-001` to `RP-003`, or `4.7.500`. A throttle backs the
  provider off for longer than a generic 4xx: 10 minutes doubling to 2
  hours for Google and Microsoft, and 15 minutes doubling to 4 hours for
  Yahoo. After the pause, sending resumes at the provider's
  `throttled_messages_per_minute` (default 60) per source address, halved
  for each further throttle (down to 1/8). The cut is lifted one step for
  every 15 minutes without another throttle.
- **Recipient replies.** A deferral about one mailbox does not back off the
  destination. That covers `4.2.2` mailbox full (at every destination, with
  or without a profile) and Google's `4.2.1` "receiving mail at a rate". The
  message still defers and retries as usual.

No built-in profile sets a connection or message rate, because none of these
providers publishes one. Set them per provider if you need to.

```toml
[[delivery.providers]]
name = "gmail"                       # override a built-in
max_connections = 10                 # per source address; default max_connections_per_domain
max_messages_per_minute = 600        # per source address; default none
throttled_messages_per_minute = 120  # after a throttle; default 60
throttle_backoff = 600               # seconds; first pause after a throttle
throttle_backoff_max = 7200
throttle_signals = ["some new reply text"]   # added to the built-in signals

[[delivery.providers]]
name = "yahoo"
disabled = true                      # shape yahoo.com per domain again

[[delivery.providers]]
name = "corp-relay"                  # a custom provider
mx_suffixes = ["mx.corp.example"]
max_connections = 4
```

### Inbound sender verification

SPF, DKIM, DMARC and ARC verification are configured under `[plugins.spf]`,
`[plugins.dkim]`, `[plugins.dmarc]` and `[plugins.arc]`. They run together
under one deadline, `[inbound_auth] timeout` (seconds, default 10); a plugin's
own `timeout` caps that check and cannot extend past the shared deadline.
`[plugins.dmarc] enforce` (default false) decides whether a DMARC `fail`
applies the sender's published policy; leave it off until you have watched the
results, since forwarders and mailing lists break SPF alignment by design.

### TLS reporting

`[tls_reporting]` sends SMTP TLS Reporting (RFC 8460) reports. For every
recipient domain, the server counts each new outbound session against the
domain's MTA-STS policy (or "no policy found"): successes, and failures by
cause (`starttls-not-supported`, `certificate-expired`,
`certificate-host-mismatch`, `certificate-not-trusted`,
`validation-failure`). After each UTC day it looks up
`_smtp._tls.<domain>` and, for domains that publish a record, emails the
report through the queue (`mailto:`) or POSTs it (`https://`). Domains
without a record are dropped silently. A failed send is retried hourly, up
to six times.

```toml
[tls_reporting]
enabled = false                         # reports are mail to third parties
report_from = "tlsrpt@example.com"      # required; must be a domain you DKIM-sign
organization_name = "Example Inc"       # default: hostname
contact_info = "postmaster@example.com" # default: report_from
# state_file = "/var/spool/elemta/tlsrpt-state.json"  # default: in the queue dir
```

Counts are saved to `state_file` every minute and on shutdown, so a restart
loses at most a minute of counts.

### DMARC aggregate reports

`[dmarc_reports]` sends DMARC aggregate reports (RFC 7489 §7.2) for inbound
mail. Each DMARC evaluation by `[plugins.dmarc]` is counted when the From
domain's record has a `rua=mailto:` tag: source IP, header From domain, the
published policy (`p`, `sp`, `pct`, `adkim`, `aspf`), the disposition applied,
whether DKIM and SPF aligned, and the underlying DKIM (domain, selector,
result) and SPF (domain, result) outcomes. Evaluations that agree on all of
these are one record with a count.

After each UTC day, every such domain is mailed one report through the queue:
RFC 7489 Appendix C XML, gzipped and attached as
`<hostname>!<policy-domain>!<begin>!<end>.xml.gz`.

- **External destinations.** A `rua` address outside the policy domain's
  organisational domain gets reports only if it publishes a TXT record
  `<policy-domain>._report._dmarc.<rua-domain>` starting `v=DMARC1` (RFC 7489
  §7.1). Otherwise anyone could point a `rua` at a victim. If that lookup
  fails rather than finding nothing, the report is retried.
- **Size limits.** A `!size` suffix (`mailto:rua@example.com!10m`) is
  honoured: a destination whose limit the report exceeds is skipped.
- **Unenforced failures.** With `[plugins.dmarc] enforce = false`, a failing
  message under `p=quarantine` or `p=reject` is reported with disposition
  `none` and reason `local_policy`.
- **Limits.** At most 10,000 records per domain per day and 10,000 domains
  per day are kept. Messages past the record limit are counted, and the
  report says how many were left out.
- **Which messages count.** The verifier evaluates DMARC against the envelope
  sender's domain. A message whose From header names a different domain is
  not counted, so a domain is never sent results for mail that was not
  evaluated under its policy.

A failed send is retried hourly, up to six times.

```toml
[dmarc_reports]
enabled = false                              # reports are mail to third parties
report_from = "dmarc-reports@example.com"    # required; use a domain you DKIM-sign
organization_name = "Example Inc"            # default: hostname
contact_email = "postmaster@example.com"     # default: report_from
# state_dir = "/var/spool/elemta"            # default: the queue directory
```

Counts are saved to `dmarc-reports-state.json` in `state_dir` every minute
and on shutdown, so a restart loses at most a minute of counts.

### Metrics

- `[metrics].enabled`
- `[metrics].listen_addr`

### Sender reputation telemetry

No configuration. Every remote delivery outcome is counted per sending pool,
per source address and per mailbox provider, alongside the existing
per-destination counts. That covers delivered, deferred, bounced, throttled
(a deferral the provider explained as rate or reputation limiting) and
complained (an ARF feedback-loop complaint). Outcomes without a pool or
provider are counted only per destination. Neither are attempts we refused
ourselves, such as a pool at its warmup cap or a destination in backoff,
because the receiver never saw them.

- **Dashboard and API.** Reports, then Sender reputation, or
  `GET /api/stats/senders?days=1` (1 to 7 UTC days). Each row has its
  complaint, bounce, deferral and throttle rates and a status:
  - `critical` at a 0.3% complaint rate, the Gmail and Yahoo limit.
  - `warning` at 0.1%, their target.
  - Bounce rates of 2% and 5% are flagged too. Those are a rule of thumb,
    not a provider limit.
  - Below 100 delivered messages the status is `low_volume`.
  The counts live in Valkey as daily buckets kept for 8 days.
- **Prometheus.** `elemta_sender_outcomes_total{dimension, key, outcome}`,
  with `dimension` one of `pool`, `ip` or `provider`.
- **Complaints.** A complaint arriving at `feedback_addresses` is counted
  against the pool and address in its `Source-IP`, but only when that is one
  of the configured pool addresses, because anyone can send a report. It is
  counted against the provider of the complaining recipient's domain. A
  report with the recipient redacted still counts. Gmail sends no
  feedback-loop reports, so read Gmail's spam rate in Google Postmaster
  Tools; a Gmail complaint rate of zero here means "not reported".

### TLS

- `[tls].enabled`
- `[tls].enable_starttls`
- `[tls].cert_file`
- `[tls].key_file`
- optional `[tls.letsencrypt]`

### DKIM (outbound signing)

- `[dkim].enabled`
- `[dkim].header_canonicalization` / `[dkim].body_canonicalization` (default `relaxed`)
- `[[dkim.domains]]` blocks with `domain`, `selector`, `private_key_path`, optional `headers_to_sign`

See [DKIM Signing](dkim-signing.md) for key generation, DNS setup, and details.

---

## Compatibility notes

- The code still supports some legacy nested fields under `[server]`.
- Prefer the top-level fields shown above for new configs.
- If no config file is found, Elemta starts with secure defaults where possible.

---

## Related docs

- [Installation](installation.md)
- [DKIM Signing](dkim-signing.md)
- [SMTP Server](smtp_server.md)
- [Queue Management](queue_management.md)
- [Queue Backend Runbook](queue-backend-runbook.md)
