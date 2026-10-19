# Mailbox two-step verification key

The mailbox service encrypts active and pending authenticator seeds in PostgreSQL
with AES-GCM. Every mailbox replica needs the same
`ELEMTA_MAILBOX_TOTP_KEYS` environment value. The supplied Compose and
Kubernetes development stacks get `v1:<base64 key>` from
`scripts/dev-secrets.sh`; the generated secret is kept in the ignored
`ldap-services.env` file and rendered into `mailbox.env`. Back up this key
separately from the database. Losing it prevents users from verifying their
existing authenticator codes.

For a separate deployment, generate a random 32-byte key, base64 encode it,
and set `ELEMTA_MAILBOX_TOTP_KEYS=v1:<base64 key>` through its secret manager.
The service refuses a malformed key. It also refuses to start if existing
authenticator records need a key and none is configured. On the first start
with a key, it encrypts older plaintext records under a database advisory
lock before accepting connections. Back up the database before that upgrade.

To rotate, first give every replica both versions as `v1:<old>,v2:<new>`.
Then restart every replica with `v2:<new>,v1:<old>`; startup rewrites existing
records under v2. Keep v1 available for older database backups and restores.
After the old backups expire, v1 can be removed. Restoring a database encrypted
with an unavailable version will fail startup rather than silently disabling
two-step verification.
