# Postgres object storage

Mail stays in the mailbox service. Calendar events, contacts, tasks and settings can
use Postgres instead of the default hidden IMAP folders. Webmail and DAV
use the same backend. Sessions continue to use their configured backend.

## Compose setup

Supply `ELEMTA_OBJECT_DB_PASSWORD` securely in your shell, then start the
optional database alongside the normal development stack:

```sh
docker compose -f deployments/compose/docker-compose.yml \
  -f deployments/compose/docker-compose.objects.yml up -d webmail-objects
```

The database has a persistent named volume and no published host port.
Keep using these two Compose files when managing this optional service.
Create a dedicated `webmail` database and role yourself when using an
external Postgres installation. The role needs permission to create the
object tables and index on first startup, and read/write access afterward.

Set these keys in the runtime configuration's existing `[webmail]` table:

```toml
object_store = "postgres"
```

Supply `ELEMTA_WEBMAIL_OBJECT_POSTGRES_DSN` in the shell or a protected
Compose `--env-file`; the optional Compose file passes it into webmail.
For the Compose database, the lib/pq DSN is
`host=webmail-objects port=5432 dbname=webmail user=webmail password=... sslmode=disable`.
Quote special characters according to lib/pq DSN rules. The optional
`object_postgres_dsn` TOML field is an alternative for protected config
files; the environment variable takes precedence. Never commit credentials.
The supplied database uses plaintext connections on the isolated development
network. External deployments should configure Postgres TLS and use
`sslmode=verify-full` with the appropriate CA certificate.

Restart every webmail replica with the same settings. Startup fails if
Postgres is unavailable or the schema cannot be initialized. It never
silently falls back to IMAP. The pool permits ten connections per process.

## Cutover and recovery

1. Back up the IMAP mailboxes and Postgres database. Stop all webmail
   replicas, including DAV traffic, before switching backends. Do not run
   IMAP-backed and SQL-backed replicas together.
2. Configure Postgres and restart all replicas. After successful IMAP
   authentication, the first login for each mailbox copies all four
   collections in one SQL transaction. Other first logins for that mailbox
   wait on the same migration row. Source read failures or resource-name
   conflicts roll back the entire copy and fail login; fix the cause and retry.
3. Check calendar, contacts, tasks and settings, then sync a DAV client.
   Back up Postgres regularly from this point onward.

The migration preserves IDs, resource names, contents and timestamps. It
keeps the hidden-folder originals intact. A completed migration is recorded
in `webmail_object_users`; reconnecting never imports those originals again,
so deleting an object in SQL does not resurrect it on the next login.
Mailbox keys are the lowercased login address with `default_domain` applied.
Account aliases must resolve to that same canonical login before use.

Returning to `object_store = "imap"` exposes the retained pre-cutover
snapshot. Changes made in Postgres are not copied back. Before rollback,
stop writers and export/reconcile new data; changing the setting alone
would hide every post-cutover edit. There is no reverse migration command.

## Integration test

Use a disposable Postgres database, with a role that can create tables:

```sh
ELEMTA_TEST_OBJECT_POSTGRES_DSN='host=127.0.0.1 dbname=objects user=objects password=... sslmode=disable' \
  go test -race -run TestPostgresObjects ./internal/webmail/
```

The test covers rollback, concurrent first migrations, mailbox isolation,
resource-name uniqueness and preservation, timestamps, binary data and
deletion without reimport. It removes its own mailbox fixtures.

For the running development stack, also set `ELEMTA_TEST_OBJECT_IMAP=1`.
This uses `stressuser20@example.com` / `testpass123`, copies its existing
objects into the disposable database, and exercises DAV against a temporary
HTTP server without switching the deployed webmail backend. Set
`ELEMTA_TEST_VDIRSYNCER` to a vdirsyncer executable to additionally check
real-client discovery, download and upload for both CalDAV and CardDAV.
The test removes its SQL fixtures and does not modify the mailbox originals.
Run it only against a disposable SQL database, never the production object store.
