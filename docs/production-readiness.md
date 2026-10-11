# Production Readiness

An honest assessment of where Elemta stands, so you can decide whether it fits
your deployment rather than discovering the boundaries in production.

Elemta is a capable, security-focused SMTP server with solid RFC fundamentals
and real operational tooling. It is not a drop-in replacement for a
purpose-built high-volume outbound platform, and this page is specific about
which use cases it does and does not cover.

## What is solid

**SMTP protocol.** RFC 5321 core, PIPELINING (RFC 2920), SIZE (RFC 1870),
STARTTLS (RFC 3207), CHUNKING/BDAT (RFC 3030), ENHANCEDSTATUSCODES (RFC 2034),
DSN parameter parsing (RFC 3461), and REQUIRETLS (RFC 8689). Line-ending
strictness is enforced by default, which closes the bare-LF SMTP-smuggling
ambiguity.

**Message intake.** DATA and BDAT bodies spool to disk past a threshold, so the
accepted message size is not bounded by memory, and the advertised SIZE limit
matches what is enforced. Enqueue is idempotent via content-hashed tombstones,
with a documented on-disk format that survives upgrade and rollback.

**Submission and relay control.** Only authenticated clients, loopback and
`allowed_relays` may relay. An authenticated client may only use a `MAIL FROM`
its login owns (`553 5.7.1` otherwise), with shared addresses granted under
`[auth.sender_aliases]`. Failed AUTH attempts are counted per client address
across connections.

**Inbound sender verification.** SPF, DKIM, DMARC and ARC verification run
together under one deadline (`[inbound_auth] timeout`, 10s by default), with
TXT answers cached briefly, so a stalled resolver cannot hold a client at
end-of-DATA. DMARC reports by default (`[plugins.dmarc] enforce = false`);
turn enforcement on deliberately.

**Content scanning.** ClamAV (INSTREAM) and Rspamd (`/checkv2`) are real
clients, not stubs. Verdicts are acted on; the reject-on-failure and
reject-on-spam policies are explicit. Messages stream to the scanners from the
spool.

**Queue backends.** `file` (default), `sqlite`, `postgres`, and `indexedfs`
(an indexed filesystem backend). Postgres enables multi-node workers with
message claims.

**Outbound authentication of your mail.** DKIM signing (fail-closed on signing
errors), with `elemta dkim` commands to generate keys and confirm DNS before a
rotation. ARC sealing is available when a key is configured.

**Outbound transport security.** MTA-STS policy is fetched and enforced on
delivery, and REQUIRETLS is honoured (stricter than MTA-STS: it mandates
verified TLS). DANE (RFC 7672, `[delivery] dane`) and SMTP TLS Reporting
(RFC 8460, `[tls_reporting]`) are implemented and off by default; DANE needs a
DNSSEC-validating resolver on loopback. TLS monitoring with configurable alert
thresholds is built in.

**Outbound delivery.** Sessions to an MX are reused for consecutive messages
(`[delivery] reuse_connections`, on by default). Each destination domain has
its own concurrency cap (`max_connections_per_domain`), optional rate cap
(`[delivery] max_messages_per_minute_per_domain`), and adaptive backoff: a
destination that defers is left alone for a doubling interval while other
domains keep flowing.

**Admin access.** Login is required by default, with roles (admin, operator,
user, readonly) managed in the dashboard or with `elemta user`, failed-login
lockout, and refusal of cross-site requests that ride the session cookie.

**Sending IP pools.** `[[delivery.pools]]` binds outbound mail to named
sets of source addresses chosen by envelope sender, with a per-address EHLO
name and an optional daily warmup schedule paced across the day; limits and
backoff apply per source address per destination. See
[Configuration](configuration.md#sending-ip-pools).

**List hygiene.** Permanent bounces and spam complaints from feedback loops
(ARF reports sent to `feedback_addresses`) suppress the recipient, and
campaigns skip suppressed addresses.

**Operations.** Prometheus-ready metrics, health endpoints with queue risk
signals (oldest-message age, connection-error rates), a web dashboard for queue
management, and a paginated API. Configuration reloads on SIGHUP or when the
file changes. A manually dispatched deploy workflow ships to a compose host
over SSH with health checks and automatic rollback; see
[Production Deployment](production-deployment.md).

## What is maturing

**Multi-node.** The Postgres backend and message claims make horizontal scaling
possible, but it is newer than the single-node file/sqlite paths. Validate
failover behaviour against your own workload before relying on it. See the
[queue backend runbook](queue-backend-runbook.md).

**Throughput.** On a single development host, a 40,000-message stress run
sustained about 130 messages per second of intake with no failures, and the
file backend drained a queue at about 140/s on average (200/s peak). That is
ample for transactional and departmental mail; it is not the
tens-of-thousands/sec regime that dedicated outbound platforms target. The
limit is inside Elemta, not the mailbox server (see `HANDOFF.md`). Measure on
your own hardware, with scanning enabled.

**Delivery and bounce handling.** Retry scheduling, deferral, and failure
queues exist. Bounce generation and DSN emission are less battle-tested than the
intake path.

**DANE and TLS reporting.** Both are new in v0.3.0 and off by default. With
DANE on, a DNSSEC lookup failure defers mail rather than sending without DANE,
so a resolver outage holds outbound mail.

## What is not here

These are the things a high-volume **outbound** platform provides that Elemta
does not, and where a purpose-built platform is the right tool:

- **Provider-aware throttling.** Per-destination limits and backoff are
  generic; there are no built-in policies keyed to Gmail, Yahoo or Microsoft
  guidance, and no shaping driven by mailbox-provider feedback.
- **Advanced deliverability telemetry.** Feedback-loop complaints suppress
  recipients, but there is no seedlist integration or engagement-based routing.

## Before you go to production

1. Read [Production Deployment](production-deployment.md) end to end,
   especially the hardening section. Create the first admin account before
   starting the web service (login is required by default), and do not copy
   `config/dev.toml`, which turns it off.
2. Check which addresses your submission users send as, and list shared or
   role addresses under `[auth.sender_aliases]` before upgrading to v0.3.0.
3. Point the content scanners at reachable addresses and decide your
   reject-on-failure posture.
4. Choose a queue backend deliberately and know its migration story
   (`queue.backend` does not migrate existing messages).
5. Provide real TLS material.
6. Load-test on your own hardware with scanning enabled; do not assume the
   numbers above.
7. Set up backups of the queue directory and configuration.

If your use case is transactional, notification, departmental, or gateway mail
with a strong security posture, Elemta is a reasonable production choice. If it
is high-volume marketing/outbound at provider scale, use a platform built for
that and consider Elemta as a submission or filtering gateway in front of it.
