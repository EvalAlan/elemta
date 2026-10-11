# Elemta Changelog

## Unreleased

### Fixes

- **DMARC now judges the header From, not the envelope sender.** It was
  evaluated against the MAIL FROM domain, so a forger could send from their own
  SPF-passing envelope domain with `From:` set to someone else's and get
  `dmarc=pass` in Authentication-Results. DMARC now uses the RFC5322.From
  domain (RFC 7489 §3.1), with SPF and DKIM alignment checked against it and
  relaxed alignment based on the public suffix list. A subdomain with no DMARC
  record of its own falls back to its organisational domain's policy (`sp=`
  when set). A message with no usable From gets `dmarc=permerror`; one naming
  several From domains never passes and takes the strictest failing policy.
  **Behaviour change:** with `[plugins.dmarc] enforce = true`, mail whose
  header From domain fails DMARC is now rejected or quarantined per that
  domain's policy even when the envelope domain passes SPF and DMARC.

### Outbound delivery

- **Sending IP pools** (`[[delivery.pools]]`). Outbound mail is bound to named
  sets of source addresses chosen by envelope sender, each address with its own
  EHLO name. An optional per-address warmup schedule caps daily volume, paced
  across the day, with counts kept across restarts. Shaping limits and backoff
  apply per source address per destination when pools are in use. No pools
  configured means no change.
- **Mailbox provider profiles** (`[delivery] provider_profiles`, on by
  default). Gmail, Yahoo and Microsoft destinations are matched by MX host and
  shaped as one destination per provider per source address, so Workspace and
  Microsoft 365 domains share their provider's limits. The providers' own
  throttle replies get a longer backoff and a slower send rate afterwards.
  Override, disable or add providers under `[[delivery.providers]]`.
- **Sender reputation telemetry.** Outcomes, provider throttles and feedback-loop
  complaints per sending pool, source address and mailbox provider: Reports →
  Sender reputation, `GET /api/stats/senders`, and
  `elemta_sender_outcomes_total`. Complaint rates are flagged at the Gmail and
  Yahoo 0.1% / 0.3% thresholds.
- **Full mailboxes no longer back off a destination.** A `4.2.2` deferral (or
  Google's per-recipient `4.2.1`) defers that message only.

### Kubernetes

- **The dev stack can also run on Kubernetes**, as an option next to Compose,
  which stays the default. `make k8s-install-dev`, `-full`, `-bench` and
  `-postgres` build the images, load them into a local cluster (k3s on
  Arch/CachyOS is the documented path) and apply an overlay of
  `deployments/kubernetes/dev`, with the same services, names and host ports.
  `make k8s-help` lists the rest (`k8s-up`, `k8s-down`, `k8s-logs`,
  `k8s-rebuild-dev`, `k8s-reseed`, `k8s-sink-up`, ...).
- **`deployments/kubernetes/standalone`**: Elemta, its dashboard, an LMTP sink
  and Valkey from the published image, for any cluster.
  `kubectl apply -k deployments/kubernetes/standalone`.
- **The old `k8s/` and `tests/k8s/` are removed.** They used the pre-TOML
  config format and a `make k8s-deploy` target that no longer existed, so they
  could not deploy the current server.
- The image now ships `deployments/sink/lmtp_sink.py` as
  `/app/tools/lmtp_sink.py`, and installs `openssl` explicitly for
  `prepare-config.sh`.

## v0.3.0 (2026-10-10)

### Breaking: authenticated senders can only send as themselves

After AUTH, `MAIL FROM` must be an address the login owns, or the server
replies `553 5.7.1 Sender address rejected: not owned by authenticated user`.
Before this, any authenticated user could send as any address, including one
in another customer's domain.

A login that is an address owns that address. A bare login (`alice`) owns
`alice@` at each of `local_domains`. The null sender is always allowed, and
unauthenticated sessions are unaffected. Grant shared or role addresses under
`[auth.sender_aliases]` (an exact address, or `@domain` for a whole domain), or
set `[auth] allow_any_sender = true` to keep the old behaviour while you list
them.

**Before upgrading:** check which addresses your submission users send as.

### Outbound delivery

- **Connection reuse** (`[delivery] reuse_connections`, on by default). The next
  message to the same MX goes over the open session instead of reconnecting:
  connect, EHLO and the TLS handshake are skipped. About 9ms to 5ms a message
  in the benchmark.
- **DANE** (`[delivery] dane`, off by default). When an MX is DNSSEC-signed
  and publishes TLSA records, its certificate must match them, with no
  fallback to plaintext. Needs a validating resolver at `dane_resolver`
  (default `127.0.0.1:53`).
- **SMTP TLS Reporting** (`[tls_reporting]`, off by default). Daily RFC 8460
  reports to domains that publish `_smtp._tls`, by mail or HTTPS.

### Sender verification is bounded

SPF, DKIM, DMARC and ARC now run together under one deadline, `[inbound_auth]
timeout` (10s by default). Before, they ran one after another, each with its
own timeout, and DKIM key lookups had none, so a stalled resolver held a client
at end-of-DATA for 20 to 36 seconds. TXT answers are cached briefly in-process.
A plugin `timeout` above `[inbound_auth] timeout` no longer has any effect.

### Deployment and tooling

- A real deploy workflow: manually dispatched, SSH to a host running
  `deployments/compose/docker-compose.prod.yml`, health-gated with automatic
  rollback to the previous image tag. See `docs/production-deployment.md`.
- The dev stack resolves through its own caching resolver (`elemta-dns`), so
  stress runs measure Elemta rather than the host's DNS. `elemta_network` now
  has a fixed subnet (10.253.53.0/24); run `make down` once to recreate it.
- `tests/performance/smtp_stress_test.py` resolves the target once instead of
  per message, and no longer counts connection errors as corpus mail.

## Upgrade Notes (August 2026)

This release changes behaviour that was previously inert. Read before rolling
out — some of it will refuse mail that a prior build accepted.

### Content scanning now actually scans

ClamAV and Rspamd were connected at startup and then never asked to scan
anything. What ran instead was a substring match against the message body for
the EICAR string and the literal words `malware`, `virus` and `trojan` — which
refused any message containing the word "antivirus", and caught no real threats.

Both are now real clients (ClamAV over INSTREAM, Rspamd over `/checkv2`), and
their verdicts are acted on:

- A virus verdict refuses the message with `554 5.7.1`.
- A spam verdict refuses only when `[antispam].reject_on_spam = true`;
  otherwise the message is delivered carrying `X-Spam-*` headers.
- If no scanner is reachable, mail is delivered **unscanned** and a warning is
  logged at startup. Set `reject_on_failure = true` only if you would rather
  refuse mail than accept it unscanned.

**Before upgrading:** confirm your scanner addresses are correct. The defaults
assume `localhost`, which is wrong when the scanners are separate containers.
A deployment that had "working" scanning without reachable scanners was not
scanning at all, and will now log the warning.

### Scanner `scan_limit` and `api_key` were silently ignored

The nested scanner config structs carried JSON tags but no TOML tags. Neither
decoder maps an underscored key onto a Go field by name, so `scan_limit` and
`api_key` were parsed and discarded while single-word keys worked. Anyone who
set them got the built-in default with nothing logged. Both now apply — check
that the values you had written are the ones you actually want, because until
now they had no effect.

### `strict_line_endings` is enforced

The setting existed but was always false regardless of configuration, because
of a config-mapping bug. It now takes effect and defaults to on.

Bare LF is a real ambiguity — RFC 5321 requires CRLF, and a message terminator
of `.\n` rather than `.\r\n` is the basis of SMTP smuggling. Legacy senders
that emit bare LF **will now be refused**. If you relay for such a sender, set
`strict_line_endings = false` while you fix the sender, and understand that you
are accepting the ambiguity in the meantime.

### `trusted_networks` decides who skips scanning

Peer classification previously matched on address prefixes and got it wrong in
both directions — `172.0.0.0/8` was treated as private (only `172.16.0.0/12`
is), and any IPv6 address whose text contained `::1` matched loopback. Trust is
now decided by real CIDR containment against the top-level `trusted_networks`
key.

The default list is deliberately narrower than what the old code accepted:
`127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`. If your internal
senders live on `192.168.0.0/16` or a ULA range, list them explicitly or they
will be scanned as external.

### `max_size` is no longer bounded by memory

Messages spool to disk past 256 KB instead of being held in memory, so the
advertised SIZE limit and the enforced one now agree. Previously a large
`max_size` was advertised and then refused. Ensure the queue directory has room
for `max_concurrent` × `max_size` in the worst case.

### Worker pool sizing

The connection worker pool was hardcoded to 20 regardless of configuration. It
now follows `[resources].max_concurrent` (default 200). A deployment relying on
the implicit 20-connection ceiling will now accept considerably more
concurrency — check that downstream capacity matches.

### Other fixes worth knowing about

- Connection reuse was broken entirely: a second message on the same connection
  was refused with `503`. Pipelining clients were affected badly.
- Commands pipelined after `DATA` were discarded rather than processed.
- A partial `[memory]` section could brick the server on startup.
- `monitoring_interval` was interpreted as nanoseconds.

---

## Latest Improvements (February 2026)

### SMTP Protocol Extensions
- **ENHANCEDSTATUSCODES (RFC 2034)**: Advertised in EHLO; all replies already use enhanced status codes
- **CHUNKING/BDAT (RFC 3030)**: Full BDAT command handler with single/multi-chunk transfer, zero-size LAST, MaxSize enforcement, and DATA/BDAT desync prevention
- **DSN (RFC 3461)**: Parsing of MAIL FROM RET/ENVID and RCPT TO NOTIFY/ORCPT parameters; stored as queue annotations for future bounce generation
- **REQUIRETLS (RFC 8689)**: Conditionally advertised when TLS is active; parsed from MAIL FROM and stored as queue annotation for future delivery enforcement

### Bug Fixes
- **SMTP Write Deadline Fix**: Fixed stale write deadline causing client hangs after 30s by using `SetDeadline()` (both read+write) in the command processing loop
- **Configurable Read Timeout**: Added `Resources.ReadTimeout` for tuning the command-loop deadline independently from the initial connection timeout
- **Auth migration control**: Added explicit `[auth].allow_deprecated_sha1` config switch (and `AUTH_ALLOW_DEPRECATED_SHA1`) so operators can disable legacy `{SHA}`/`{SSHA}` verification ahead of removal

## Previous Improvements (January 2026)

### Enhanced Logging & Monitoring
- **Delivery IP Address Logging**: Added `delivery_ip` and `delivery_host` fields to message delivery logs for enhanced tracking
- **Improved Log Categorization**: Fixed categorization logic for spam/virus/4xx/5xx SMTP responses to ensure proper separation of rejection, deferral, and system logs
- **Comprehensive Log Filtering**: Enhanced web interface log filtering with accurate event type classification

### Web Interface Enhancements
- **Reports Chart Time Scales**: Added time scale selector with Hourly, Daily, Weekly, and Monthly views for delivery trend analysis
- **Chart Y-Axis Fix**: Resolved missing y-axis issue on reports page charts with proper tick marks and value labels
- **Adaptive Chart Rendering**: Charts now automatically adjust label frequency based on data length and time scale

### API Improvements
- **Enhanced Delivery Stats API**: Added `timeScale` parameter to `/api/stats/delivery` endpoint for flexible data aggregation
- **Backward Compatibility**: Maintained existing `by_hour` field while adding new `data` field for generic time-scale responses

## Previous Improvements (June 2025)

### Email Security & Scanning
- **Added ClamAV and Rspamd Integration**: Messages now scanned for viruses and spam
- **Security Headers**: Added proper X-Virus-Scanned, X-Spam-Scanned, X-Spam-Score, X-Spam-Status headers
- **Plugin System**: Enhanced builtin plugin system for antivirus and antispam

### Network-Based Relay Control
- **Smart Relay Logic**: Internal networks can relay without authentication, external networks require auth
- **Private Network Detection**: Automatic recognition of RFC 1918 and RFC 4193 private networks
- **Local Domain Support**: Always allow delivery to configured local domains

### LDAP Authentication
- **Complete LDAP Integration**: Full authentication against LDAP/Active Directory
- **Secure Connection Handling**: Proper LDAP SSL/TLS support
- **User Management**: Dynamic user authentication without local user database

### Email Delivery Pipeline
- **LMTP Integration**: Direct delivery to Dovecot via LMTP protocol
- **Queue Management**: Enhanced message queuing with priority handling
- **Delivery Tracking**: Comprehensive logging and monitoring of message delivery

### Web Interface & Management
- **Roundcube Integration**: Full webmail interface for users
- **Management Dashboard**: Administrative interface for monitoring and control
- **User-Friendly Setup**: Automated configuration and deployment

### Testing & Quality
- **Comprehensive Test Suite**: Organized test files for all major features
- **Automated Testing**: Scripts for validating SMTP, LDAP, relay, and delivery functionality
- **Docker Environment**: Complete containerized testing environment

### Documentation
- **Relay Control Documentation**: Detailed explanation of network-based relay behavior
- **Test Documentation**: Organized test suite with clear instructions
- **Security Documentation**: Guidelines for secure email handling

### Configuration
- **Enhanced Configuration**: Support for local domains, internal networks, and authentication settings
- **Docker Compose**: Complete stack with LDAP, Dovecot, monitoring, and web interface
- **Environment Variables**: Flexible configuration for different deployment scenarios 