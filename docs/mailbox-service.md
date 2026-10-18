# Elemta mailbox service

`elemta mailbox` runs an independent IMAP/LMTP mailbox service with Postgres
metadata and immutable filesystem or S3 message bodies. It is the first
implementation of the [mailbox architecture](mailbox-engine-architecture.md).
The normal development Compose stack now uses this service. Existing Maildir
data must be imported into separate metadata/body volumes using the
[offline cutover procedure](mailbox-dev-cutover.md). The isolated demo and HA
labs remain optional; Dovecot is available only for explicit rollback.

## Implemented

- LDAP bind authentication and recipient/alias lookup using a read-only
  service identity. Directory `entryUUID` owns data; address reuse does not
  grant access to a previous account's mailbox. Directory quotas are enforced.
- Transactional folder creation, subscription, rename/delete, append,
  flags/keywords, copy/move and expunge. UIDs and UIDVALIDITY survive restart
  and database promotion. Account rows serialize conflicting writers across
  processes; no process-local lock owns authoritative state.
- IMAP4rev1 with UIDPLUS, MOVE, NAMESPACE, IDLE, LIST-EXTENDED, LIST-STATUS,
  SPECIAL-USE, ESEARCH, STATUS=SIZE, SORT and SORT=DISPLAY,
  THREAD=REFERENCES and THREAD=ORDEREDSUBJECT, QUOTA (read only) and ID.
  STARTTLS is available with configured certificates. Only implemented
  extensions are advertised. SORT, THREAD, QUOTA and ID come from a fork of
  go-imap's server in `internal/imapfork` (see its `FORK.md`).
  With `server.allow_plaintext_auth=false`, both IMAP authentication and
  LMTP delivery require TLS; LDAP must use verified LDAPS. The existing queue
  LMTP client still needs STARTTLS support before a secure production cutover.
- MIME envelopes, body sections and structures, raw download and search.
  Deep/malformed MIME has a bounded structure fallback; original bytes stay
  downloadable.
- Message summaries in Postgres, computed once per stored body: header
  block, envelope, MIME structure, sort/thread keys and search index columns.
  Message lists (ENVELOPE, BODYSTRUCTURE, header fields), SORT and THREAD
  never read bodies. Mail stored before summaries existed is summarised on
  first use, by a background backfill (`maintenance.backfill_batch` per
  minute per replica) or at once with `elemta mailbox backfill`.
- Indexed SEARCH. From, To, Cc, Bcc, Subject and Content-Type are matched as
  case-insensitive substrings on stored decoded values. BODY and TEXT match
  words by prefix against a Postgres text search vector of the readable body
  text (GIN indexed), as indexed IMAP servers do. Other header fields, and
  patterns without letters or digits, are evaluated from the stored header
  block or the body.
- LMTP with per-recipient results and retry deduplication when trusted clients
  supply a stable ENVID. Elemta's queue transport now supplies a hash of its
  own queue ID when DSN is advertised, and correctly dot-stuffs message data.
  Identical content with different delivery IDs remains distinct mail.
- Body checksums and immutable publication on file and S3 backends. Ceph RGW
  uses the S3 driver; a real Ceph cluster has not been qualified yet. Bodies
  are bounded in memory, concurrent body operations are limited, and metadata
  pools and protocol connections have explicit limits.
- Durable change records, MODSEQ counters and upload intents. Cross-process
  IDLE notifications check folder state once a second and replay only the
  changes since the session's MODSEQ, so their cost doesn't grow with the
  folder. The journal is compacted after `maintenance.journal_retention_hours`
  (a week by default); a session that fell behind reloads its folder.
- Readiness checks for a writable database and accessible body store. Strict
  mode requires configured synchronous replication and a streaming quorum/
  synchronous standby. Writes explicitly use synchronous commit in that mode.
  Before acknowledgment, a post-commit WAL barrier on the original primary
  connection verifies that the configured number of synchronous standbys
  flushed the commit. This also covers uncertain commit-wait cancellation.

## Daily Compose development

With the existing normal Compose stack running:

```sh
make mailbox-dev-up
make mailbox-dev-status
```

This creates the read-only `cn=mailbox,ou=services,...` LDAP account, builds
`elemta-mailbox:dev`, and starts a separate four-container project:

| Component | Local endpoint | Role |
|---|---|---|
| `edge` | `127.0.0.1:11443` | Plaintext development IMAP |
| `edge` | `127.0.0.1:12424` | LMTP; only trusted Docker delivery peers allowed |
| `edge` | `http://127.0.0.1:18031/readyz` | Dependency readiness |
| `mailbox-a`, `mailbox-b` | Internal | Two service processes using the same metadata and bodies |
| `metadata` | Internal | One development Postgres instance |

Memory caps total 2.125 GiB; they are not a capacity measurement. The two
service replicas share a named body volume. This tests replica loss and
restart recovery, but its database, proxy, disk and host remain single
failure points. This optional project does not change the normal SMTP/webmail
routing or share its mailbox data. There is no automatic import into this lab.

The real service config is [`config/mailbox.toml`](../config/mailbox.toml).
The Compose file is
[`docker-compose.mailbox.yml`](../deployments/compose/docker-compose.mailbox.yml).
Credentials are generated into ignored `.secrets/` files. The PostgreSQL
connector uses `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` and
`PGSSLMODE`, or a lib/pq DSN in `ELEMTA_MAILBOX_DATABASE_DSN` (the env-variable
name is configurable with `metadata.dsn_env`). Never print or commit the
resolved Compose config with its environment values.

The named volumes use Docker's root filesystem, observed at about 503 GiB
free when this service was introduced. The repository filesystem's larger
free space is not automatically available to those volumes.

```sh
# Stop containers, retain their data.
make mailbox-dev-down
```

### Optional webmail against the new engine

```sh
./scripts/mailbox-dev.sh webmail
```

Open `http://localhost:18037` and sign in with a development mailbox account
such as `user@example.com` / `password`. This is a separate webmail instance
using a separate, initially empty mailbox store. Port 8027 uses the normal
mailbox deployment and its migrated data. Sessions in this optional demo are
deliberately process-local. Sending uses the normal SMTP submission server,
whose destination is the normal mailbox store, so replies do not automatically
arrive in this isolated lab. Use its LMTP port for test delivery.
Calendar/contacts/tasks/settings use the new engine's hidden IMAP folders;
there is no copy of the existing user's hidden folders in this demo.

### S3 and Ceph

```sh
make mailbox-dev-s3
```

This starts an optional SeaweedFS S3 fixture at `127.0.0.1:18333`, creates the
`mailbox-dev` bucket and uses generated credentials. It does not change the
running mailbox backend. The contract tests exercise this real S3 endpoint.

For a new/migrated metadata database, set `ELEMTA_MAILBOX_BODY_DRIVER=s3`
before starting the service; the development config includes the internal
fixture endpoint. For Ceph/AWS, configure `bodies.endpoint` as host[:port]
without a URL scheme, `bucket`, `region`, `secure=true`, and credential env
names. The S3 identity needs bucket-existence checks and object get/put/delete;
conditional create must work. Private CAs must be installed in the trust
store. No automatic bucket creation or insecure certificate bypass is used.

Do not switch backends under existing mail: startup refuses when referenced
objects belong to another configured storage identity. File identities
include the configured root path; S3 identities include endpoint and bucket.
A backend migration command has not been implemented. Pointing two local
file roots at different disks under the same pathname does not replicate
mail; production file deployments require qualified shared storage.

## HA failover lab

```sh
make mailbox-ha-dev-up
make mailbox-ha-dev-status
```

This builds a separate ten-container project: three Postgres 17/Patroni
members, three etcd voters, two mailbox replicas and two edge/database
proxies. The bootstrap helper waits for two streaming quorum standbys before
starting mailbox replicas. Metadata uses `ANY 1` synchronous replication,
strict quorum mode and an application role with no superuser privileges.
`pg_monitor` lets readiness inspect replication status. Each engine uses its
paired proxy for writable-primary routing; that proxy closes database
connections when its primary check fails. Schema initialization is serialized.

| Endpoint | Edge A | Edge B |
|---|---|---|
| IMAP | `127.0.0.1:11445` | `127.0.0.1:11446` |
| LMTP | `127.0.0.1:12426` | `127.0.0.1:12427` |
| Readiness | `http://127.0.0.1:18035/readyz` | `http://127.0.0.1:18036/readyz` |

These are independent entry points; the test client retries the alternate.
There is no pretend redundant localhost VIP. Both engines share the lab's
separate body volume. The daily stack and HA lab do not share mail data.
Memory caps total about 7.125 GiB. Stop the lab with
`make mailbox-ha-dev-down`; volumes are retained.

Patroni bootstrap settings apply only when initializing a new cluster. Edit
live dynamic settings with Patroni's management tools; changing the YAML's
bootstrap section does not reconfigure an existing cluster. The lab has
plaintext internal links and container-local bootstrap trust; database REST
APIs and etcd are internal to the lab network. Do not expose these management
ports or use this configuration as a production security policy.

The lab demonstrates process loss and promotion, not physical host/zone
independence. Its shared disk, LDAP server and Docker daemon remain shared
failure domains. Hardware watchdog fencing is disabled for the container
lab; production needs verified fencing, TLS, replicated body storage,
redundant directory/ingress and rehearsed backups. The normal SMTP queue also
needs replicated durability before claiming zero loss of all accepted mail.

## Publication, retries, cleanup and backups

Each append registers a unique upload intent, durably writes the body, then
publishes mailbox metadata in one transaction. UID allocation, quota usage,
retry result and change record commit together. A failed upload or metadata
transaction cannot expose partial mail. A retry token reused for different
bytes fails. Tokens are per account and envelope recipient, remain recorded
after a message is moved/deleted, and do not use Message-ID as identity.

Interrupted uploads become cleanup candidates after ten minutes. Ready
bodies become candidates only after all memberships are gone and a full day
of grace has elapsed. Cleanup locks and rechecks references; retired keys
cannot acquire new references. Retired rows are kept as durable tombstones
and deletion is retried daily, covering a late orphan from a stalled upload.
These records and the change/delivery journals currently have no compaction
policy; measure and implement retention before large deployments.

Automatic body cleanup is **off by default**. An operator may explicitly set
`[maintenance] garbage_collection = true` only when the fixed one-day grace
is compatible with backup retention. The worker processes bounded batches.
For longer restore windows, keep automatic cleanup off until configurable,
backup-aware retention is implemented. Removing metadata and running cleanup
can otherwise make an older database backup unrestorable.

Back up Postgres and bodies as a coordinated recovery set, including TLS and
directory credentials. A filesystem/object copy without its metadata does
not preserve mailbox UIDs, memberships or flags. Replication does not replace
backup or protect against accidental deletion. Test isolated restores.

## Verification

```sh
# Require a disposable database; core SQL tests skip when this is absent.
ELEMTA_TEST_MAILBOX_DSN='host=127.0.0.1 port=15432 dbname=objects user=objects password=... sslmode=disable' \
  go test -race -count=1 ./internal/mailbox/

# Exercise deployed endpoints and clean up only its own fixture folder/mail.
ELEMTA_TEST_MAILBOX_PASSWORD=password python3 scripts/test-mailbox-dev.py --failover
ELEMTA_TEST_MAILBOX_PASSWORD=password python3 scripts/test-mailbox-dev.py --ha --failover --quorum-loss
```

The live script defaults to `user@example.com`; override with `--user`.
It creates a unique folder and unique-subject mail and cleans them up. The
failure modes deliberately stop/restart only the isolated project's replicas,
database primary, edge and coordination members. Run against a quiet lab,
not an unrelated deployment or concurrent failure-injection session.

S3 contract tests additionally use `ELEMTA_TEST_MAILBOX_S3_ENDPOINT` and
`MAILBOX_S3_ACCESS_KEY` / `MAILBOX_S3_SECRET_KEY` from the protected fixture
environment. They verify binary bytes, conditional immutability, restart
reads, retries and refusal to switch to missing storage.

Core tests cover independent writer pools, UID allocation, restart state,
quotas, copy/move/expunge, interrupted writes, expired upload fencing, cleanup,
account/address isolation and cross-replica IDLE. CI runs them against Postgres.

## Remaining replacement gates

This service can receive and serve mail; it is not yet a complete Dovecot
replacement or a demonstrated million-mailbox deployment. Keep the existing
server until these remaining gates are met:

- ManageSieve/Sieve execution, vacation and duplicate-suppression semantics.
- CONDSTORE/QRESYNC.
- Measured memory limits for very large mailboxes: a selected session still
  holds one small row per message in its view.
- Backend/account migration, UID-preserving import, placement automation,
  tenant/cell management and live ownership fencing administration.
- Backup-aware garbage retention, restore drills and production TLS/fencing.
- Real Ceph testing, sustained load and additional desktop/mobile client QA.

The PostgreSQL and body-storage HA requirements are described in the
[architecture proposal](mailbox-engine-architecture.md); the local lab does
not establish end-to-end production availability by itself.
