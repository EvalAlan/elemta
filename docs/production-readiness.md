# Production Readiness

An honest assessment of where Elemta stands, so you can decide whether it fits
your deployment rather than discovering the boundaries in production.

Elemta is a capable, security-focused SMTP server with solid RFC fundamentals
and real operational tooling. It is not a drop-in replacement for a
purpose-built high-volume outbound platform such as KumoMTA or Momentum, and
this page is specific about which is which.

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

**Content scanning.** ClamAV (INSTREAM) and Rspamd (`/checkv2`) are real
clients, not stubs. Verdicts are acted on; the reject-on-failure and
reject-on-spam policies are explicit. Messages stream to the scanners from the
spool.

**Queue backends.** `file` (default), `sqlite`, `postgres`, and an indexed
filesystem backend. Postgres enables multi-node workers with message claims.

**Outbound authentication of your mail.** DKIM signing (fail-closed on signing
errors).

**Outbound transport security.** MTA-STS policy is fetched and enforced on
delivery, and REQUIRETLS is honoured (stricter than MTA-STS: it mandates
verified TLS). TLS monitoring with configurable alert thresholds is built in.

**Operations.** Prometheus-ready metrics, health endpoints with queue risk
signals (oldest-message age, connection-error rates), a web dashboard for queue
management, and a paginated API. Rate limiting and trusted-network
classification are configurable.

## What is maturing

**Multi-node.** The Postgres backend and message claims make horizontal scaling
possible, but it is newer than the single-node file/sqlite paths. Validate
failover behaviour against your own workload before relying on it. See the
[queue backend runbook](queue-backend-runbook.md).

**Throughput.** On a single node in a noisy shared test environment, sustained
intake measured in the low hundreds of messages per second with content
scanning enabled, dominated by per-message scanner round trips. That is ample
for transactional and departmental mail; it is not the tens-of-thousands/sec
regime that dedicated outbound platforms target. Measure on your own hardware.

**Delivery and bounce handling.** Retry scheduling, deferral, and failure
queues exist. Bounce generation and DSN emission are less battle-tested than the
intake path.

## What is not here

These are the things a high-volume **outbound** platform provides that Elemta
does not, and where KumoMTA/Momentum are the right tool:

- **Sending IP pools / virtual MTAs.** No per-pool source-IP binding, no
  per-destination shaping and warmup policy, no automatic traffic shaping to
  mailbox-provider feedback.
- **Provider-aware throttling.** No built-in per-destination concurrency and
  rate policy keyed to Gmail/Yahoo/Microsoft guidance.
- **Advanced deliverability telemetry.** No native FBL processing, seedlist
  integration, or engagement-based routing.
- **Some transport-security extras.** MTA-STS is implemented; DANE/TLSA record
  validation and TLS-RPT reporting are not.

## Before you go to production

1. Read [Production Deployment](production-deployment.md) end to end,
   especially the hardening section — the admin API is **unauthenticated by
   default** and the dev compose binds it to all interfaces.
2. Point the content scanners at reachable addresses and decide your
   reject-on-failure posture.
3. Choose a queue backend deliberately and know its migration story
   (`queue.backend` does not migrate existing messages).
4. Provide real TLS material.
5. Load-test on your own hardware with scanning enabled; do not assume the
   numbers above.
6. Set up backups of the queue directory and configuration.

If your use case is transactional, notification, departmental, or gateway mail
with a strong security posture, Elemta is a reasonable production choice. If it
is high-volume marketing/outbound at provider scale, use a platform built for
that and consider Elemta as a submission or filtering gateway in front of it.
