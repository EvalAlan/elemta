# Elemta Changelog

## Unreleased

### Upgrade notes

- **The directory has a new image.** `elemta-ldap` now runs OpenLDAP 2.6.15
  on Alpine 3.24 (`ghcr.io/evalalan/elemta-ldap`, built with each release)
  instead of `osixia/openldap`, which was no longer maintained and shipped
  OpenLDAP 2.4.57. The two databases aren't compatible, so the directory
  moves to new volumes: `scripts/cloud-deploy.sh` does it with
  `scripts/ldap-migrate.sh`, which exports the entries with the previous
  image, creates the new directory from them, reapplies the access rules
  and service passwords, and checks every entry arrived. Logins pause for
  about a minute. If you roll service by service, run the script first; the
  new directory refuses to start empty while the old data is there. The old
  volumes are left as they were for a rollback.
- Backups no longer include the directory's configuration files; a restore
  creates the directory afresh from its entries (`ldap/data.ldif`), so
  backups taken before this release restore the same way.

### Features

- **The directory carries mail settings** ([directory.md](docs/directory.md)).
  Accounts can forward all mail elsewhere, optionally keeping a copy, and can
  be allowed to send as other addresses (aliases, lists, shared addresses or a
  whole domain); both are editable in the dashboard and with
  `elemta provision modify-account --forward/--keep-copy/--send-as`. A
  directory can also assign classes of service to accounts and domains, hold
  distribution lists as groups (member DNs and member addresses), and hold
  mail domains with their catch-all and alias. Where the directory sets
  something it wins; elsewhere the dashboard's settings apply, and a class
  chosen for an account in the dashboard still overrides the directory's.
- Accounts have a real object class, `elemtaMailAccount`, instead of
  `extensibleObject`, which switched schema checking off for each account;
  lists (`elemtaMailList`) and domains (`elemtaMailDomain`) have theirs.
  `scripts/ldap-schema.sh` adds the definitions to an existing directory and
  moves the accounts over; deploys run it.

### Fixes

- The directory now keeps `memberOf` for `groupOfNames`, the group style
  Elemta creates; it was set up for another style, so `memberOf` never
  filled in.
- The unused `ou=mailgroups` branch is no longer created (and is removed when
  empty), the demo directory data uses the current schema, and the old demo
  deploy script, which targeted the previous mailbox server, is gone.
- `{SSHA512}` passwords, which Elemta writes when a user's password is set
  through the directory, can now be checked by the directory; the previous
  image lacked the module. Password changes made with the LDAP Password
  Modify operation are stored as `{SSHA512}` too.

### Security

- The directory container runs slapd as an unprivileged user on a read-only
  root filesystem with only the capabilities to bind port 389 and drop
  privileges.

## v0.5.3 (2026-10-21)

A performance patch for the webmail. No configuration or schema changes.

### Upgrade notes

- Set `ELEMTA_TAG` to `v0.5.3`. Only the webmail's behaviour changes;
  rolling back to v0.5.2 is a matter of changing the tag.

### Performance

- Each page view in the webmail no longer opens its own connection to the
  mailbox for live updates. One connection per user is shared between their
  pages, kept for 30 seconds after the last one closes, and replaced every
  few minutes so a changed password or a disabled account still ends it.
- The shared-mailbox switcher is cached for a minute per session instead of
  reauthenticating on every page; the mailbox still authorizes every access.
- Opening a message fetches it once instead of twice: the reading pane
  reuses the copy the page just read (messages up to 2 MB, for 30 seconds,
  dropped on any change to messages or on sign-out).
- Measured on the development server: about 85% fewer authentications and
  half as many folder selections per webmail action, 20 to 25 percent more
  actions per second, and the slowest 5% of actions about a fifth faster.

### Repository

- Removed outdated handoff and planning notes; the docs, `make gotchas` and
  this changelog carry what they held that still applies.

## v0.5.2 (2026-10-21)

This patch release adds two administration features and makes the mailbox
and webmail faster under load.

### Upgrade notes

- Set `ELEMTA_TAG` to `v0.5.2`. Schema changes (the account status and the
  administrator access tokens) apply on start and are additive, so rolling
  back to v0.5.1 keeps working.
- The mailbox database now starts with `pg_stat_statements` preloaded, so
  `docker compose up -d` recreates `elemta-mailbox-db` once; the mailbox
  replicas reconnect within seconds. To read the statistics, run
  `create extension if not exists pg_stat_statements` in the database.
- The dashboard's Open mailbox action needs `ELEMTA_WEBMAIL_PUBLIC_URL`; the
  internet-facing overlay sets it from `MAIL_DOMAIN`.

### Features

- Accounts can be suspended: a suspended account keeps receiving mail but
  cannot sign in to the webmail, IMAP, POP3, SMTP or calendar and contacts
  sync. Disabled accounts still neither sign in nor receive.
- Domain administrators can open a user's mailbox in the webmail from the
  dashboard. Access lasts one hour, is recorded in the audit log, shows a
  banner naming the administrator, and cannot send mail, switch to shared
  mailboxes or use calendar and contacts sync.

### Performance

- Folder listings and counts look up each message's body by key instead of
  hashing the whole body table: the folder query fell from 13 ms to 1.4 ms on
  the development server's mailbox, and IMAP, POP3 and webmail throughput
  under load rose by roughly 10 to 20 percent.
- Signing in to the webmail republishes the user's free/busy times at most
  once an hour; edits in the webmail and over CalDAV still publish at once.

## v0.5.1 (2026-10-20)

This patch release brings the changes since v0.5.0 into the pinned production
images. It fixes delivery reporting and avoids refusing legitimate archived
mail during load testing.

### Upgrade notes

- Keep using the three-file production Compose stack and set `ELEMTA_TAG` to
  `v0.5.1` after the tag images are published. No schema migration is needed.
- The minimum Go version for source builds is 1.26.10. The container builds
  use Go 1.27.3 to include the October `crypto/x509` security fix.
- `[message_checks]` has `header_mode` and `body_mode` (`reject`, `warn`,
  `off`). The default `reject` preserves existing discretionary checks;
  `max_header_length = 0`, `strict_address_headers = false` and
  `reject_invalid_utf8 = false` continue to leave the known false-positive
  checks off. See [configuration.md](docs/configuration.md).
- Rspamd's numeric-IP URL symbol is scored once at five points. A numeric
  link still contributes to spam classification, but repeating it no longer
  makes an ordinary newsletter cross the reject threshold by itself.

### Fixes

- Webmail's Mail, Calendar, Contacts and Tasks tabs have icons; messages
  with legacy 8-bit header and body charsets display as text.
- Reports show daily, weekly and monthly charts, balanced cards and accurate
  delivery trends based on per-recipient outcomes.
- SMTP AUTH LOGIN accepts an initial response and keeps credentials out of
  logs. Header field names accept RFC 5322 punctuation. The optional
  unfolded-header length, address and UTF-8 checks can be disabled; the
  remaining discretionary header and body checks can warn or be turned off.
- Load tests confirmed all submitted messages in the measured runs arrived
  once. The scaling results and measured bottlenecks are in
  [load-performance.md](docs/load-performance.md).

## v0.5.0 (2026-10-20)

The release where Elemta becomes a complete self-hosted mail platform: its
own mailbox service and webmail replace the third-party IMAP server and PHP
webmail the stack used before, with administration, sharing, compliance and
production tooling around them. It is also the first release published as a
git tag, with container images on ghcr.io.

### Upgrade notes

- **License:** Elemta is now GPL-3.0-only (was MIT).
- **The third-party IMAP/LMTP/Sieve server and the PHP webmail are gone**
  from Compose, Kubernetes, scripts and docs; `elemta-mailbox` and
  `elemta-webmail` take their place. The old source-system integration
  command and package are removed; use `elemta migrate` to move users.
- **Dashboard read endpoints** (queues, logs, traces, statistics,
  configuration) now need the `api:read` permission. Every existing role has
  it, so nothing changes for current users; the new `domain-admin` role
  doesn't.
- **Mailbox TLS 1.2** accepts only forward-secret AEAD suites; mail clients
  older than about 2013 that can only do CBC suites can't connect.
- New Postgres tables and columns are created on start
  (`IF NOT EXISTS`, no table rewrites): classes of service, lists and
  routes, held mail, audit log, free/busy, shares.

### Mailbox service

- IMAP4rev1/rev2 with CONDSTORE/QRESYNC, SORT, THREAD, QUOTA, IDLE, indexed
  SEARCH, set-based STORE/EXPUNGE/COPY/MOVE; POP3; LMTP; Sieve with
  vacation and ManageSieve. Metadata in Postgres, bodies on disk or S3, any
  number of replicas behind HAProxy.
- Implicit TLS on 993, STARTTLS-only IMAP and POP3 on public ports, LMTP over
  STARTTLS from the MTA; sessions hold only UIDs, so memory doesn't grow with
  folder size.
- `mailbox verify`, backup and restore drill.

### Webmail

- Mail with conversations, rich compose, search, filters and out-of-office,
  tags, folders, light and dark themes, push of new mail.
- Calendar with invitations and replies, holidays, tasks, contacts;
  CalDAV/CardDAV sync; optional Postgres object storage.
- Two-step verification (TOTP, recovery codes) and app passwords for mail
  apps; verified password recovery.
- **Company address book** in address autocomplete (accounts and lists of
  your own domain) and **free/busy**: guests' busy times on the event form,
  published from each user's calendar without titles.
- **Shared mailboxes**: members open them in webmail and in mail apps
  (`member|mailbox` as the user name) with their own password, and send as
  them when granted.

### Administration

- **Classes of service**: quotas, message and attachment sizes, sending
  limits, protocol switches, forwarding, filters, app-password and two-step
  requirements, per domain or account with overrides.
- **Retention and legal hold**: Trash/Junk expiry and maximum mail age;
  legal hold keeps everything deleted, exportable as mbox, and blocks purge.
- **Distribution lists, domain aliases and catch-alls**, with posting
  policies.
- **Domain administrators** (`domain-admin` role, `--domains`): manage their
  domains' accounts, aliases, lists and catch-alls and nothing else.
- **Audit log** of every administrative change (dashboard, CLI, migration)
  in Postgres, with a dashboard page.
- `elemta provision reset-two-factor`, shared-mailbox grants, purging.
- **`elemta migrate`**: mail over IMAP (incremental, idempotent), calendars
  and contacts from `.ics`/`.vcf`, accounts, aliases and lists from CSV.
- Mail over a recipient's size limit is refused at RCPT.

### Operations

- **Release images** `ghcr.io/evalalan/elemta` and
  `ghcr.io/evalalan/elemta-mailbox`, tagged with the version.
- **Production overlay** `docker-compose.release.yml` for the full stack:
  release images, third-party images pinned by digest, no-new-privileges,
  memory and process limits and read-only root filesystems
  (docs/production-compose.md).
- **Backup and restore** of the whole stack: `scripts/backup.sh`,
  `scripts/restore-drill.sh`, `scripts/restore.sh`.
- Kubernetes overlays run the mailbox service and webmail; Valkey for the
  dashboard and MTA.

## v0.4.0 (2026-10-11)

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
- **Pool state shared across nodes** (`[delivery] shared_state`, off by
  default). Warmup caps and mailbox provider throttles are kept in Valkey, so
  several nodes sending from the same addresses share one daily cap and one
  backoff. Without Valkey, or while it is unreachable, each node counts on its
  own as before. Pools are now reloaded with the configuration.

### Bounces

- **Delivery status notifications follow RFC 3464.** Final-Recipient is the
  address tried and Original-Recipient carries ORCPT; ENVID and ORCPT are
  decoded; remote server text is reduced to printable ASCII and folded, so it
  cannot add fields or parts; each bounce gets its own Message-ID; local errors
  are labelled `X-Elemta` rather than `smtp`.
- **No bounces to MAILER-DAEMON or this host's postmaster**, so two servers
  cannot bounce at each other.

### DMARC aggregate reports

- **`[dmarc_reports]`** (off by default). Daily RFC 7489 aggregate reports to
  domains that publish `rua=mailto:`, gzipped XML through the queue, with
  external destination verification and `!size` limits honoured. Counts
  survive a restart.

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
