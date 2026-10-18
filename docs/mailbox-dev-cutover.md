# Development mailbox cutover

The normal Docker Compose stack uses Elemta's mailbox service, with two
stateless engine processes behind a health-aware proxy. PostgreSQL owns mailbox
metadata and a shared named file volume holds immutable message bodies. Webmail
stays on port 8027, IMAP on 14143 and LMTP on 2424. SMTP submission stays on 2587.
The mailbox engines use the directory's immutable account ID for ownership.
The discarding sink is stopped and belongs to the explicit benchmark profile;
`make sink-up` starts it when throughput testing is needed.

This compact, single-host development deployment has one PostgreSQL instance,
one ingress proxy and one local body volume. It does not demonstrate host or
storage high availability. The separate `make mailbox-ha-dev-up` lab exercises
metadata failover; production needs independently placed database voters,
replicated bodies, redundant ingress and directory service, fencing and tested
restores. See [the architecture](mailbox-engine-architecture.md) and
[service limitations](mailbox-service.md).

## Existing development mail

Do not point existing users at an empty database. First build both images and
create the metadata database:

```sh
make ensure-dev-secrets ldap-service-accounts
docker compose -f deployments/compose/docker-compose.yml build elemta elemta-mailbox-a
docker compose -f deployments/compose/docker-compose.yml up -d --no-deps --wait elemta-mailbox-db
```

Stop SMTP, webmail and any external mail clients. Preserve the existing runtime
configuration privately. `scripts/export-mailbox-snapshot.py --output <private-path>`
disables the source network protocols, disconnects clients, exports metadata
using `doveadm`, restores the on-disk protocol configuration for rollback, stops
Dovecot, and copies the whole mail volume. If export fails, the source stays
quiesced: restore `/tmp/before-mailbox-export.conf` to
`/etc/dovecot/dovecot.conf` inside the container before restarting it.
The export keeps orphaned/deleted-account Maildirs in the snapshot but imports
only accounts enumerated by the directory.

Mount that snapshot read-only into a one-off engine container while both engine
services and the proxy are stopped. The container UID (1001) must be able to read
it; keep its host parent directory private. For example:

```sh
docker compose -f deployments/compose/docker-compose.yml run --rm --no-deps \
  -v /absolute/private/snapshot:/snapshot:ro elemta-mailbox-a \
  mailbox --config /etc/elemta/mailbox.toml import --offline --snapshot /snapshot
```

Run the import a second time before starting services: an exact retry reads and
checks every message body, UID, flags and internal date against the snapshot.
Each folder publishes atomically. Interrupted uploads stay tracked for cleanup;
completed folders are accepted only if unchanged. UIDVALIDITY, UID gaps,
UIDNEXT and subscriptions survive. Hidden Calendar, Contacts, Tasks and Settings
folders are included. Existing over-quota source data is retained; subsequent
new deliveries still enforce the directory quota. Maildir LF is converted to
the CRLF bytes exposed over IMAP. Do not use the importer against live mail.

Change the **existing runtime configuration**, preserving other settings:
`[delivery] host = "elemta-mailbox"`, port 2424;
`[webmail] imap_addr = "elemta-mailbox:1143"`, `imap_tls = "none"`,
`sieve_addr = ""`. Keep a private backup of the previous runtime configuration.
Start the two engines and proxy with `up -d --no-deps --wait`, then recreate
SMTP and webmail using `ELEMTA_CONFIG_RESEED=false` and `--no-deps`.
Verify source hashes and UIDs over IMAP, actual submission-to-LMTP delivery,
webmail sign-in/read/send, hidden objects and IDLE updates before calling the
cutover complete. Never reseed the entire runtime configuration just to change
these three settings.

## Retained source and rollback

Dovecot remains defined under the explicit `dovecot-rollback` profile. Normal
`make install-dev` and Compose startup no longer start it. Its `dovecot_data`
volume is retained. No cleanup target should delete that volume or the private
snapshot until migration and backups are accepted.

Before any rollback, stop SMTP, webmail and the mailbox proxy. Preserve the new
metadata and bodies, and reconcile **all mail and object changes since cutover**
back to the source; the original volume is only a pre-cutover snapshot. There
is no automated reverse migration. Restoring the old volume alone would hide
new mail and edits. After reconciliation, restore the private runtime-config
backup and start Dovecot explicitly with `--profile dovecot-rollback up -d
--no-deps elemta-dovecot`, then recreate SMTP/webmail without dependencies or
reseed. The proxy and Dovecot bind the same host ports and cannot run together.
Roundcube, if used, also needs its IMAP host/port restored.

## Current compatibility limits

The new engine does not yet implement ManageSieve, delivery filters or vacation
replies. The dev fixture's only saved script has no rules and vacation is off;
its files remain in the source snapshot. Webmail explicitly shows filters as
unavailable. An installation with active rules must implement and qualify
those actions before cutover. Search currently scans message data rather than
using a full-text index; server-side SORT/THREAD and advanced synchronization
extensions remain pending. Webmail uses its existing fallback paths, including
individual messages in the conversation view. These are development limits,
not production parity claims.
