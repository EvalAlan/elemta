# Elemta mailbox service

`elemta mailbox` runs an independent IMAP/LMTP mailbox service with Postgres
metadata and immutable filesystem or S3 message bodies. It is the first
implementation of the [mailbox architecture](mailbox-engine-architecture.md).
It is the mail store of the development Compose stack, which no longer
includes Dovecot; mailboxes start empty. The isolated demo and HA labs remain
optional.

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
  THREAD=REFERENCES and THREAD=ORDEREDSUBJECT, QUOTA (read only), ID,
  CONDSTORE and QRESYNC (clients resynchronise from the MODSEQ they last
  saw; VANISHED comes from the change journal, or from the UIDs that no
  longer exist once the journal has been compacted).
  STARTTLS, and implicit TLS on `server.imaps_listen` (normally :993), use
  `tls_cert`/`tls_key`, which are re-read when the files change so renewals
  need no restart. Only implemented extensions are advertised. SORT, THREAD, QUOTA and ID come from a fork of
  go-imap's server in `internal/imapfork` (see its `FORK.md`).
  With `server.allow_plaintext_auth=false`, both IMAP authentication and
  LMTP delivery require TLS; LDAP must use verified LDAPS. Elemta's LMTP
  clients (delivery and RCPT-time recipient checks) use STARTTLS when
  `[delivery] lmtp_tls = "starttls"`, verified against `lmtp_tls_ca_file`
  or the system roots, and never fall back to plaintext.
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
- Sieve filtering at delivery and ManageSieve (RFC 5804) on `sieve.listen`.
  Supported: fileinto (with `:create`, `:copy` and flags), keep, discard,
  redirect, reject/ereject, imap4flags, variables, relational, regex, body,
  envelope, subaddress, environment, date/currentdate and vacation (with
  `:seconds`). The interpreter is a fork of go-sieve in `internal/sievefork`
  (see its `FORK.md`). Scripts are stored in Postgres, so every replica runs
  the same active script. A script that doesn't compile or fails at run time
  keeps the message. Retried LMTP deliveries don't store, redirect or reply
  twice. Out-of-office replies follow RFC 5230 and RFC 3834: at most one per
  sender per period, none to lists, bulk or automated mail, bounces or mail
  that doesn't name the user, sent from the null sender. Redirects and
  replies are submitted to `sieve.submit_addr`; without it they are skipped
  and logged.
- The company address book and free/busy, on the account-security API with
  the user's own credentials and limited to their own domain.
  `GET /v1/directory` lists the domain's active accounts (from LDAP, with
  `displayName` or `cn`) and distribution lists, cached for five minutes;
  the webmail adds them to address autocomplete. `PUT /v1/freebusy` stores
  the busy times the webmail computes from a user's calendar
  (`mailbox_freebusy`: start, end and tentative only, half a year ahead),
  and `GET /v1/freebusy?address=…&from=…&to=…` returns colleagues' times.
  An address in another domain answers exactly like one that never
  published.
- A selected IMAP session keeps only its folder's UIDs (4 bytes a message)
  and loads flags, dates and sizes for the messages a command touches, so
  memory doesn't grow with the folder. Measured on the dev stack: 400
  sessions on a 30,001-message folder use about 100 MB per replica.
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

Interrupted uploads become cleanup candidates after ten minutes. A ready body
becomes a candidate only once no message refers to it: cleanup marks it
then, and removes it `[maintenance] body_grace_hours` later (a week by
default) if it is still unreferenced. The grace counts from that mark, not
from the upload, so an old message deleted today stays recoverable from a
backup taken yesterday. Cleanup locks and rechecks references; retired keys
cannot acquire new references. Retired rows are kept as durable tombstones
and deletion is retried daily. The change journal is compacted after
`journal_retention_hours`.

Automatic body cleanup is **off by default**. Turn it on with
`[maintenance] garbage_collection = true` once `body_grace_hours` is longer
than your backup retention.

### Backup and restore

Back up the metadata and the bodies together, metadata first:

```sh
scripts/mailbox-backup.sh /path/to/backup        # pg_dump, then the bodies
scripts/mailbox-restore-drill.sh /path/to/backup # restore beside the stack and verify
```

Bodies are written before the metadata that refers to them and their
contents never change, so a dump taken first refers only to bodies the copy
that follows will include. On S3, bucket versioning or replication can stand in for the
body copy.

`elemta mailbox verify` checks that every body a message refers to exists
with its recorded size and checksum, and that each account's quota usage
matches its messages. Run it after every restore (the drill script does)
and periodically in production; `--sample N` checks a random N bodies on
large stores. Keep TLS and directory credentials with the backups. A copy
of either half alone doesn't preserve mailboxes, and replication doesn't
replace backups. Run the drill regularly.

### Encrypting message bodies

With `ELEMTA_MAILBOX_BODY_KEYS` set, message bodies are encrypted with
AES-256-GCM before they reach the file or S3 store. Each body gets its own
derived key and is bound to its object, so a moved or altered object fails to
open. Anyone with only the bucket or the bodies volume gets ciphertext.

**This protects the body store, nothing else.** PostgreSQL still holds message
summaries (subject, sender, recipients, preview) and the search index, which
contains the words of each message; use disk encryption and protected database
backups for those. Mail is readable by the server while it is handled, and an
administrator with the key can read everything. It is not end-to-end encryption.

**Losing the key loses the mail.** There is no recovery. Keep a copy somewhere
that doesn't share a failure with the server, and away from the bucket:
encryption protects nothing if the key sits beside the data. `scripts/backup.sh`
includes it in `secrets.tar.gz`, so set `BACKUP_AGE_RECIPIENT`.

To turn it on with the cloud deploy:

1. Set `MAILBOX_BODY_ENCRYPTION=true` in `.secrets/cloud.env` and run
   `scripts/cloud-deploy.sh`. It creates `.secrets/mailbox-body-keys.env` once
   and never replaces it.
2. Copy that file off the server, and run a backup.
3. Encrypt what is already stored. New mail is encrypted from step 1, and old
   mail stays readable until this reaches it. It can run while the service does,
   and can be stopped and run again:

   ```sh
   docker exec elemta-mailbox-server-1 /app/elemta mailbox encrypt-bodies --config /etc/elemta/mailbox.toml
   docker exec elemta-mailbox-server-1 /app/elemta mailbox verify --config /etc/elemta/mailbox.toml
   ```

Every body is checked against its recorded checksum first and read back after.
One that doesn't match is reported and left alone. Encrypted copies don't erase
earlier ones: remove old versions if the bucket is versioned, and remember that
existing backups still hold plaintext.

For any other deployment, generate 32 random bytes, base64 encode them, and set
`ELEMTA_MAILBOX_BODY_KEYS=v1:<base64 key>` the same way on every replica.

Every key's fingerprint is recorded in the database. A replica with a different
key under the same version refuses to start, because it would write mail the
others can't read, and so does a service with no keys on a store that has used
them, so a lost environment file can't silently turn encryption off.

To rotate, set `v2:<new>,v1:<old>` on every replica, restart them, and run
`encrypt-bodies` again. Keep v1 until no backup you might restore needs it.

## Verification

```sh
# Require a disposable database; core SQL tests skip when this is absent.
ELEMTA_TEST_MAILBOX_DSN='host=127.0.0.1 port=15432 dbname=objects user=objects password=... sslmode=disable' \
  go test -race -count=1 ./internal/mailbox/
```

Checks against a deployed mailbox service (failover, quorum loss) belong
with the other live tests in the separate elemta-tests repository.

S3 contract tests additionally use `ELEMTA_TEST_MAILBOX_S3_ENDPOINT` and
`MAILBOX_S3_ACCESS_KEY` / `MAILBOX_S3_SECRET_KEY` from the protected fixture
environment. They verify binary bytes, conditional immutability, restart
reads, retries and refusal to switch to missing storage.

Core tests cover independent writer pools, UID allocation, restart state,
quotas, copy/move/expunge, interrupted writes, expired upload fencing, cleanup,
account/address isolation and cross-replica IDLE. CI runs them against Postgres.

## Status and remaining gaps

The mailbox service is the mail store of the development Compose stack, the
[cloud deployment](cloud-dev.md) and the Kubernetes dev overlay, where a
Service takes HAProxy's place in front of the replicas. Dovecot is gone from
all of them. The service serves
the IMAP extensions mainstream clients rely on, along with POP3, Sieve,
ManageSieve, two-step verification and app passwords. It has been exercised
with the webmail, Thunderbird, scripted IMAP and POP3 clients, and the
backup and restore drill.

It has not yet been demonstrated as a large production deployment. Before
relying on it at scale:

- Migration tooling: import from an existing server that preserves UIDs, and
  account placement, tenant and cell management.
- Production fencing administration across replicas.
- Real Ceph or other S3 testing, sustained load, and wider desktop and mobile
  client QA.
- A production Compose file or chart that includes the service
  (`docker-compose.prod.yml` doesn't yet).

The PostgreSQL and body-storage HA requirements are described in the
[architecture proposal](mailbox-engine-architecture.md); the local lab does
not establish end-to-end production availability by itself.
