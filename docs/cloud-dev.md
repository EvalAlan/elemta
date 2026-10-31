# Cloud dev server

One internet-facing server running the whole stack with a real domain, real
certificates and real mail flow: the place to test mail clients, deliverability
and the webmail from outside a LAN. It is the development stack
(`deployments/compose/docker-compose.yml`) with an overlay
(`docker-compose.cloud.yml`), not the production deployment
(`docker-compose.prod.yml`).

The host name is also the mail domain (for example `dev.example.net`, with
addresses like `you@dev.example.net`). Use a subdomain of your own domain, never a
domain whose mail is handled elsewhere.

## What is public

| Port | Service |
|------|---------|
| 25   | SMTP, inbound mail (MX) |
| 587  | Submission, STARTTLS and login required |
| 993  | IMAPS |
| 143  | IMAP, STARTTLS required before authentication |
| 110  | POP3, STLS required before authentication |
| 80, 443 | Webmail and mail-client autoconfig, through Caddy (Let's Encrypt) |

Everything else is bound to 127.0.0.1 on the server:

- the admin HTTPS proxy, on 8025 (unless explicitly exposed below)
- LDAP, on 1389
- rspamd, on 11334
- valkey
- metrics
- plaintext IMAP
- LMTP
- ManageSieve

Reach any of them over SSH, for example:

```
ssh -L 8025:127.0.0.1:8025 you@dev.example.net
```

For admin HTTPS through this tunnel, resolve the mail domain to 127.0.0.1
locally and open `https://<domain>:8025`, preserving the certificate's hostname.

For direct admin access from a fixed IPv4 address, first add an exception to
`/etc/nftables/docker-guard.nft` before its final drop rule:

```
iifname "eth0" meta l4proto tcp ct status dnat ct original proto-dst 8025 ip saddr 203.0.113.10 accept
```

Validate and load the file with `nft -c -f` and `nft -f`. Only after the guard
is active, set `ELEMTA_ADMIN_BIND_IP=0.0.0.0` and
`ELEMTA_ADMIN_ALLOWED_IP=203.0.113.10` in `.secrets/cloud.env`. Recreate
`elemta-admin` first, then `elemta-caddy`. Caddy serves
`https://<domain>:8025` with the domain's public certificate and independently
checks the client IP. The admin backend has no published host port. Keep
8025 out of `public_ports`: the final drop rule must block every other source.
The default admin proxy binding and allowed IP remain loopback.

ManageSieve stays private because the mailbox service accepts plaintext logins
from the webmail on the internal network. Filters are edited in the webmail.

Docker's published ports bypass firewalld, so binding to loopback is what keeps a
port private. Host hardening (below) adds a second check that doesn't depend on
the compose file being right.

## Host preparation

These steps were done once for Rocky Linux 10 on a 2 vCPU / 4 GB Linode.

- **Firewall.** firewalld's public zone allows ssh, smtp, smtp-submission, imaps,
  http and https. Cockpit and rpcbind are disabled.
- **SSH.** Keys only, set in `/etc/ssh/sshd_config.d/10-hardening.conf`; root
  logs in by key only. fail2ban runs its sshd jail.
- **Updates.** `dnf-automatic` applies security updates daily.
- **Docker.** Docker CE, with these settings in `/etc/docker/daemon.json`:
  - `"firewall-backend": "nftables"`, because the Linode kernel lacks the
    iptables `addrtype` module the default backend needs;
  - `"userland-proxy": false`, so connections keep their real source address.
    With the proxy, a client connecting over IPv6 reaches Elemta from the
    Docker gateway, a private address that `allowed_relays = ["private"]`
    trusts, which makes an open relay.
- **Docker port guard.** `/etc/nftables/docker-guard.nft`, loaded by
  `docker-guard.service`, drops internet traffic to any published container port
  other than 25, 80, 110, 143, 443, 587 and 993.
- **Swap.** A 2 GB swapfile, because ClamAV alone wants about 1.5 GB.

## Deploying

The simplest way is the setup wizard, on the server itself:

```
git clone https://github.com/EvalAlan/elemta.git && cd elemta
make install        # choose 2, "a mail server for a real domain"
```

It checks DNS and the host, applies the host preparation above (asking
first), deploys, and creates the first accounts. `scripts/setup.sh --check`
runs only the checks.

To deploy by hand, or to update a server from a checkout on your
workstation, send the committed tree to the server and run the deploy script
there:

```
git archive HEAD | ssh you@dev.example.net 'mkdir -p ~/elemta && tar -x -C ~/elemta'
ssh you@dev.example.net 'cd ~/elemta && scripts/cloud-deploy.sh'
```

The first time, create `deployments/compose/.secrets/cloud.env` on the server:

```
MAIL_DOMAIN=dev.example.net
```

`scripts/cloud-deploy.sh` does the following:

1. Generates the service credentials (`scripts/dev-secrets.sh`).
2. Renders `config/elemta.toml` and `config/mailbox-main.toml` for MAIL_DOMAIN
   into `.secrets/cloud/`. The rendering:
   - sets the local domain, host name, TLS paths, DKIM signing, webmail origin
     and trusted proxy;
   - fails if any edit no longer matches the template.
3. Creates a DKIM key.
4. Builds the images.
5. Starts LDAP and creates an empty directory: the schema, the organizational
   units and the service accounts, with no demo users.
6. Waits for Caddy's certificate and starts everything.
7. Installs `elemta-cert-sync.timer`, which copies renewed certificates to the
   mail services twice a day. They re-read the files without a restart.
8. Prints the DNS records to publish.

Run it again to upgrade: domains, plugin settings and everything else saved in
the admin console stay. `scripts/cloud-deploy.sh --reseed` replaces them with
the rendered configuration, after saving a copy as
`.secrets/cloud/elemta.toml.before-reseed-<time>`. Use that only to take a
change to the rendering, such as a new default in the script.

## DNS

| Record | Value |
|--------|-------|
| `A dev.example.net` | server IPv4 |
| `MX dev.example.net` | `10 dev.example.net.` |
| `TXT dev.example.net` | `v=spf1 a mx -all` |
| `TXT <selector>._domainkey.dev.example.net` | printed by the deploy script |
| `TXT _dmarc.dev.example.net` | optional; without it the parent domain's policy applies |
| `SRV _imaps._tcp.dev.example.net` | `0 1 993 dev.example.net.` |
| `SRV _submission._tcp.dev.example.net` | `0 1 587 dev.example.net.` |
| Reverse DNS of the IPv4 address | `dev.example.net`, set at the hosting provider |

Leave out an AAAA record unless the stack is given IPv6. Outbound mail leaves
over IPv4, and receivers reject IPv6 senders without reverse DNS.

The parent domain's DMARC policy (`sp=`, or `p=` without one) covers the
subdomain. Outbound mail passes it through DKIM, signed with `d=` exactly the
subdomain, and through SPF on the envelope sender.

## More mail domains

The server can also host mail for other domains, each with its own mail host
`mail.<domain>`. List them in `.secrets/cloud.env`, separated by spaces:

```
EXTRA_MAIL_DOMAINS="example.org"
```

before the first deploy. For each one it:

- adds the domain to `local_domains`, so it accepts mail and accounts for it;
- creates a DKIM key, signing as the domain itself (`d=example.org`);
- adds `mail.<domain>` to the webmail's Caddy site, so Caddy obtains and
  renews its certificate;
- copies that certificate into `.secrets/mailbox-tls/sni/mail.<domain>/`.
  SMTP, IMAP and POP3 serve it to clients that ask for `mail.<domain>`
  (TLS SNI), and the primary certificate to everyone else;
- prints the domain's DNS records.

The host name the server announces in SMTP stays `MAIL_DOMAIN`.

On a server that is already running, add a domain in the admin console
instead: **Mail Administration → Domains** for the domain and its DKIM key, and
the **Certificates** page for `mail.<domain>`. Adding it to `cloud.env` later
has no effect without `--reseed`, and the deploy warns about it.

Move a domain that already has mail elsewhere in this order:

1. Publish the DKIM record and add this server to the SPF record (the printed
   `v=spf1 mx -all` is enough once the MX points here). Under a strict DMARC
   policy (`p=reject; adkim=s`) a message that fails both is rejected outright.
2. Point `mail.<domain>` at the server and request its certificate, or wait
   for the twice-daily sync, until `mail.<domain>` has its certificate.
   Until then its clients get the primary certificate and refuse it.
3. Create the accounts.
4. Move the MX last.

Removing a domain from the list stops serving its certificate and accepting
its mail. Its accounts and mailboxes stay until deleted.

### Certificates page

The admin console's **Certificates** page lists every certificate the mail
services serve (names, source, expiry), the one each local domain's clients
get (a domain without one is flagged), and requests still waiting. An
administrator can:

- **request Let's Encrypt certificates** for up to ten host names at once, such
  as a mail host and its alternatives, all already pointing at the server. Caddy
  obtains and renews one certificate per name, and the mail services pick by the
  name a client asks for, so clients can't tell that from one naming them all;
- **upload a certificate** chain and unencrypted key in PEM, filed under the
  certificate's first name (a wildcard `*.example.org` as
  `wildcard.example.org`). It serves every name in it. It isn't renewed;
- **remove** either kind, and **sync now**.

Certificates for `MAIL_DOMAIN` and `EXTRA_MAIL_DOMAINS` come from
`cloud.env` and can't be removed there.

The console runs unprivileged and never talks to Caddy or writes the served
certificates. It writes requests into `.secrets/cert-sync/requests/` (`hosts`,
`uploads/<host>/`, and `request` to ask for a run). `elemta-cert-sync.path`
then runs `scripts/cloud-sync-certs.sh`, which checks every request again
(host name syntax, key matches certificate, unexpired, names its host),
updates Caddy's site names, installs the certificates, removes ones no longer
wanted, and reports in `.secrets/cert-sync/status.json`. The twice-daily
timer runs the same script, so renewals are copied without anyone asking.

## Accounts

The directory starts empty. Create the domain's accounts with the provision
command, which prompts for the password:

```
docker exec -it elemta-admin /app/elemta -c /app/runtime-config/elemta.toml \
    provision create-account you@dev.example.net --name "Your Name"
```

To create an admin console login, run `make bootstrap-admin` on the server.

Forgotten-password mail is sent from `noreply@<domain>`, so the feature needs
that account. Put its password in `.secrets/webmail.env` as
`ELEMTA_WEBMAIL_RECOVERY_SMTP_PASSWORD`, then restart elemta-webmail.

## Mail clients

Thunderbird finds the settings by itself at
`https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`. Other clients
need the manual settings:

- IMAP: `<domain>`, port 993, SSL/TLS; or port 143, STARTTLS
- POP3: `<domain>`, port 110, STARTTLS (STLS on the wire)
- SMTP: `<domain>`, port 587, STARTTLS
- Username: the full address

## Stress testing

The cloud stress runner (`stress/cloud_stress.py` in the separate
elemta-tests repository) exercises verified SMTP,
IMAPS and webmail from a separate workstation, using isolated accounts and
local recipients. Start with its smoke profile before increasing concurrency.
Host settings, credentials and run reports stay outside tracked source.

### Directory bootstrap and password recovery

`scripts/dev-secrets.sh` generates a directory admin credential in the ignored,
mode 0600 `.secrets/ldap-admin.env`. The LDAP container reads it at bootstrap;
`scripts/ldap-admin-password.sh` applies it to existing directory volumes and
verifies the bind. Bootstrap operations and health checks use local socket
EXTERNAL authentication. Application services retain their separate credentials.
After upgrading an existing deployment, generate secrets, apply the script, then
recreate only the LDAP container with the usual Compose files and environment.
Neither a full config reseed nor an application password change is needed.

Create the configured recovery sender mailbox with `elemta provision`, and store
its generated credential as `ELEMTA_WEBMAIL_RECOVERY_SMTP_PASSWORD` in the server's
ignored `.secrets/recovery-smtp.env` (mode 0600). Run `scripts/dev-secrets.sh` to
refresh the per-service env files, then recreate webmail with config reseeding
disabled. The override survives later deploys; never put this password in TOML
or tracked files. A plain container restart does not reload env-file changes.

Each user must add a different accessible recovery address in webmail Settings
and confirm the verification email before Forgot password can send reset links.
Links expire after 15 minutes and are consumed only on form submission. Test
verification, reset, old-password rejection, session revocation and link reuse
with disposable accounts before relying on recovery for a real mailbox.

### Public STARTTLS mailbox listeners

The public IMAP listener uses `imap_starttls_listen` (container port 11143),
separate from the internal development IMAP listener on 1143. It never permits
plaintext authentication, regardless of `allow_plaintext_auth`. POP3 uses
`pop3_listen` (container port 1110) and always requires STLS before USER/PASS.
Both require the configured TLS certificate and support its existing reload
path. Empty listener settings disable these optional endpoints. Port 993
continues to provide implicit TLS IMAP. When upgrading an existing cloud host,
add TCP 110 and 143 to both firewalld and the Docker guard's public port set.

POP3 exposes INBOX using the same accounts, bodies and metadata as IMAP. It
supports CAPA, USER/PASS over TLS, STAT, LIST, UIDL, RETR, TOP, DELE, RSET, NOOP
and QUIT. UIDLs combine folder UIDVALIDITY with message UID. Each authenticated
session sees a fixed numbering snapshot; later arrivals appear on reconnect.
Deletion marks remain local until QUIT, when only those UIDs are deleted in
one quota/journal transaction. Disconnecting or RSET preserves the messages.
A shared PostgreSQL lease excludes simultaneous POP sessions across replicas;
a crashed server's lease expires after 15 minutes. Sessions time out after
10 minutes of inactivity. IMAP can still independently move or expunge messages;
a concurrently removed message may become unavailable to POP retrieval.

### Two-step verification and app passwords

Users turn both on themselves, in webmail **Settings → Two-step verification
and app passwords**.

- **Two-step verification** (TOTP, RFC 6238) asks for a code from an
  authenticator app after the password. It works with Aegis, 2FAS, Google
  Authenticator, 1Password and similar apps.
  - Turning it on shows a QR code, then ten one-time recovery codes.
  - A recovery code signs the user in once if the phone is lost.
  - Turning it off requires a current code.
  - Each code is accepted once, wrong codes count toward the login failure
    limit, and an app password can't sign in to webmail.
- **App passwords** are random per-app passwords, stored only as hashes. Each
  one shows when it was last used and can be deleted on its own.
  - They work on IMAP (993, 143), POP3 (110), SMTP submission (587) and
    CalDAV/CardDAV.
  - With **Require app passwords for mail apps** on, all of those refuse the
    account password, which then works only in webmail.
  - Users with two-step verification should turn this on. Otherwise a stolen
    password can still read mail over IMAP or POP3, or send it.
  - SMTP AUTH asks the mailbox service's API
    (`ELEMTA_AUTH_MAILBOX_SECURITY_URL`). Only the webmail's fixed address
    (`ELEMTA_AUTH_APP_PASSWORD_EXEMPT`, 10.253.53.250) may submit with the
    account password, because it asks for the second step itself. If the
    API is unreachable, other account-password logins are refused rather
    than let through.

The mailbox service stores both in Postgres (`mailbox_security`,
`mailbox_app_passwords`). The webmail manages them through the mailbox service's
internal API on the proxy's health port, which is never published. The API also
refuses clients outside `lmtp_allowed_networks`. Each request carries the user's
own credentials. Settings change only with the account password, so a leaked app
password can't remove the protection.

If a user loses both the phone and the recovery codes, an administrator turns
two-step verification off. Run this on the server, with the user's address:

```
docker exec elemta-mailbox-db psql -U mailbox -d mailbox -c \
  "UPDATE mailbox_security SET totp_secret=NULL,totp_pending=NULL,recovery_codes='{}' \
   WHERE account=(SELECT id FROM mailbox_accounts WHERE lower(address)=lower('user@example.net'))"
```
