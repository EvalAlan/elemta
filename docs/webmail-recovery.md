# Password recovery and live mail updates

Users add a recovery email in **Settings → Password recovery**, confirm their
current password, then follow the verification email. The address remains
inactive until they press **Verify recovery email**. A pending replacement does
not disable their previously verified address. Submitting an empty address
removes recovery and invalidates pending verification and reset links.

**Forgot password?** on the sign-in page sends a link only to the verified
address. Its response is the same for unknown accounts and accounts without
recovery. Links expire after 15 minutes, are consumed atomically on form
submission, and are stored only by a SHA-256 digest. Opening a link does not
consume it, allowing email scanners to follow it safely. A reset invalidates
other outstanding links and ends existing webmail sessions across instances.
Phone and desktop mail apps need the new mailbox password too. An already
connected external mail client may stay connected until the mail server closes
its connection; webmail session revocation does not terminate those clients.

## Configuration

Recovery records must be available while IMAP authentication is unavailable, so
recovery uses Valkey rather than the mailbox's Settings folder. Configure
persistent Valkey storage and include it in backups; verified recovery addresses
have no expiry. Tokens and cooldowns expire automatically.

Add these keys to `[webmail]`, alongside the existing IMAP, SMTP and LDAP keys:

```toml
session_store = "valkey"
valkey_addr = "valkey:6379"
session_key_file = "/run/secrets/webmail-session.key"
recovery_url = "https://mail.example.com"
ldap_reset_dn = "cn=webmail-reset,ou=services,dc=example,dc=com"
recovery_sender = "no-reply@example.com"
recovery_smtp_user = "no-reply@example.com"
```

Supply `ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD` and
`ELEMTA_WEBMAIL_RECOVERY_SMTP_PASSWORD` as secrets in the webmail process.
Alternatively use `ldap_reset_password` and `recovery_smtp_password` in a
protected configuration file. Recovery fails startup if these secrets are absent.
The existing `ldap_search_dn` remains the read-only lookup account for ordinary
password changes; the separate reset account needs lookup and password-reset
permissions. Use encrypted LDAP and SMTP connections in production. Choose a
dedicated SMTP service account that mailbox users cannot reset themselves.

`recovery_url` is a fixed public origin, never derived from an HTTP Host header.
HTTPS is required unless `secure_cookies = false` is explicitly set for local
HTTP development. An empty `recovery_url` hides self-service recovery. The local
compose configuration enables recovery on `http://localhost:8027` using its test
LDAP administrator and the existing test sender mailbox; those defaults are for
development only. Change the origin if opening the stack from another machine.

The public request endpoint has shared per-address and per-IP cooldowns. A
recovery store outage prevents resets rather than bypassing revocation. If the
directory rejects the new password, request another link and choose a stronger
password. If email delivery fails, the public response stays generic; operators
can check the webmail error log. Reset and verification tokens are not logged.
Configure any reverse proxy access logs to omit query strings on these routes.

## Administrator reset

Run on the server, with the same Valkey configuration and privileged LDAP secret
as the webmail service:

```sh
elemta --config /path/to/elemta.toml webmail reset-password user@example.com
```

The command prompts for the new password twice on a terminal. With redirected
stdin it reads one line, so automation can supply a secret without placing it
in shell arguments. It resets the mailbox password in LDAP, revokes webmail
sessions, and invalidates recovery links. It requires shared Valkey sessions;
there is no unauthenticated administrator-reset HTTP endpoint. The command can
also run with self-service recovery disabled, using `ldap_reset_dn` and its
secret.

## Instant mail updates

The browser opens `/api/events`, an authenticated Server-Sent Events stream.
Independent read-only IMAP connections run IDLE on INBOX and the currently
viewed folder. Arrivals, expunges and flag changes trigger the existing unread
badge and message-list refresh. The message list keeps its selection/menu
protection and new-mail notification behavior.

Streams send heartbeat comments every 20 seconds and reconnect every four
minutes to recheck authentication. Closing the page cancels its watchers. Each
session is limited to three streams (at most six IDLE connections plus its
ordinary mail connection). Configure the IMAP server's connection limits for
the expected number of concurrent browser tabs. Reverse proxies must permit SSE
and disable buffering for `/api/events`; the server sends `X-Accel-Buffering: no`.
If IDLE or SSE is unavailable, the browser falls back to checks every minute.
IDLE watches INBOX and the current folder; other folders' badges are reconciled
when a watched folder changes or the page regains focus.

Run the ordinary webmail tests, plus the real Valkey check when available:

```sh
go test ./internal/webmail/... ./cmd/elemta/...
ELEMTA_TEST_VALKEY=127.0.0.1:6379 go test ./internal/webmail/...
```
