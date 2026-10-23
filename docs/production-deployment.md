# Production Deployment

This is the maintained production-oriented deployment guide for the current codebase.

**Deployment target: one Docker host per environment, over SSH.** The
`Deploy` workflow (`.github/workflows/deploy.yml`, run by hand from the
Actions tab) copies `deployments/compose/docker-compose.prod.yml` and
`scripts/deploy/remote-deploy.sh` to the host and runs the script, which
pulls the image CI already built for that commit, brings the stack up, waits
for it to be healthy, and rolls back to the previous tag if it is not. No
environment is provisioned yet: until one is, the workflow stops at its
first step and says which settings are missing. See
[Setting up an environment](#setting-up-an-environment).

## Deployment models

1. **Containerized** (recommended operationally for this repo)
2. **Native package/systemd** (proposed, not shipped; see [Native Install Spec v1](native-install-spec-v1.md))

---

## 1) Containerized production baseline

Production uses `deployments/compose/docker-compose.prod.yml`, not the dev
stack in `docker-compose.yml`. It runs the image from ghcr.io rather than
building one, and leaves out everything development-only: self-issued
certificates, demo data, Roundcube and the sink. It runs the MTA and admin
console only: it does not yet include the directory, the mailbox service or
the webmail. To run the whole stack on one host, use the
[cloud deployment](cloud-dev.md). The
dashboard and metrics bind to loopback, so put a TLS reverse proxy in front
of the dashboard. Valkey runs with `noeviction`. The file's header lists the
`.env` settings it reads.

### Preparing a host

1. Install Docker Engine with the compose plugin, and create a deploy user
   in the `docker` group.
2. Put `elemta.toml`, the TLS certificate and key, DKIM keys and the users
   file in `/etc/elemta`, or set `ELEMTA_CONFIG_DIR` in `.env`. Inside the
   container the server must listen on `:2525` (MX) and `:2587`
   (submission); the host maps 25 and 587 onto those.
3. Create the deploy directory (default `/opt/elemta`) owned by the deploy
   user, with an `.env` holding any settings you want to change. The deploy
   script only ever rewrites the `ELEMTA_TAG` line.

### Setting up an environment

In the repository go to Settings > Environments, create `staging` and/or
`production`, and add:

| Kind | Name | Value |
|---|---|---|
| variable | `DEPLOY_HOST` | host name or address |
| variable | `DEPLOY_USER` | the deploy user |
| variable | `DEPLOY_PATH` | optional, default `/opt/elemta` |
| variable | `DEPLOY_PORT` | optional, default `22` |
| secret | `DEPLOY_SSH_KEY` | private key for the deploy user |
| secret | `DEPLOY_KNOWN_HOSTS` | output of `ssh-keyscan -H <host>`, after checking the fingerprint |

The host key is pinned, so CI never trusts a host it hasn't seen before. Add
required reviewers to `production` to gate deploys. The host pulls from
ghcr.io with the job's own short-lived token and logs out afterwards, so no
registry credential stays on it.

### Deploying

Go to Actions > Deploy > Run workflow, pick the environment, and leave the
tag empty to deploy the commit you are running from (it must be on `main`,
where Docker Build pushes an image per commit). You can also give any
earlier commit SHA. The workflow checks that the image exists before it
touches the host.

By hand on the host, the same thing is:

```bash
cd /opt/elemta
bash remote-deploy.sh <commit-sha>
```

---

## 2) Minimal production TOML profile

Written for `docker-compose.prod.yml`, so paths are the container's: the host's
`ELEMTA_CONFIG_DIR` (default `/etc/elemta`) is mounted at `/app/config`, and
the queue volume at `/app/queue`. The server listens on 2525 and 2587 and the
host maps 25 and 587 onto them; the compose file binds metrics and the
dashboard to loopback on the host, so they listen on all addresses inside.

```toml
hostname = "mail.example.com"
listen_addr = ":2525"            # MX: anyone may deliver to local_domains
max_size = 52428800
local_domains = ["example.com"]
failed_queue_retention_hours = 72

[server]
listen_submission = ":2587"      # submission: log in over STARTTLS, or be in allowed_relays

[queue]
dir = "/app/queue"
backend = "sqlite"

[queue.sqlite]
path = "/app/queue/queue.db"
busy_timeout_ms = 5000
journal_mode = "WAL"
synchronous = "NORMAL"

[auth]
enabled = true
# Keep required = false on an MX. It refuses MAIL FROM from every client that
# has not logged in, which includes every server delivering mail to you.
# The submission port still requires a login (or an allowed_relays address).
required = false
datasource_type = "ldap"

[tls]
enabled = true
enable_starttls = true
cert_file = "/app/config/certs/fullchain.pem"
key_file = "/app/config/certs/privkey.pem"

[api]
enabled = true
listen_addr = ":8025"
web_root = "/app/web/static"
auth_enabled = true
auth_file = "/app/config/users.txt"

[metrics]
enabled = true
listen_addr = ":8080"

[queue_processor]
enabled = true
interval = 10
workers = 20
```

---

## 3) Validation checklist

```bash
# SMTP reachable
nc -vz 127.0.0.1 25

# API health (no login needed)
curl -s http://127.0.0.1:8025/api/health | jq

# Queue stats (prompts for the admin password)
curl -s -u admin http://127.0.0.1:8025/api/queue/stats | jq

# Queue storage backend info
curl -s -u admin http://127.0.0.1:8025/api/queue/storage | jq
```

---

## 4) Hardening checklist

- Keep API bound to loopback (`127.0.0.1`) unless explicitly proxied.
- Require SMTP auth for relay paths where appropriate.
- Enforce TLS with valid cert/key paths.
- Store config/auth/queue paths with least-privilege permissions.
- Keep regular backups of queue data and config.
- Run `make test` / `make lint` before deployment changes.

### Turning authentication on

`elemta user` manages the users file; nothing else is needed to enable auth.

```bash
# Create the first account (prompts for the password twice; 12+ characters).
elemta user add admin --role admin --file /etc/elemta/users.txt

elemta user list   --file /etc/elemta/users.txt
elemta user role alice operator --file /etc/elemta/users.txt
elemta user passwd admin --file /etc/elemta/users.txt
elemta user remove alice --file /etc/elemta/users.txt
```

After the first admin exists, accounts can also be managed in the dashboard
under **Settings > Users**. Both edit the same file, and a running server picks
up changes on its next request; removing an account or resetting its password
signs it out.

Then point the server at it:

```toml
[api]
auth_enabled = true
auth_file = "/etc/elemta/users.txt"
```

The file holds `username:bcrypt-hash:role` lines and is written `0600`. **It must be
readable by the user the server runs as** — in the container that is `elemta`
(uid 1001), not the account that created the file. Getting this wrong is fatal
at startup and the process exits; with a restart policy in place that becomes a
restart loop, so check the logs for:

```
Failed to create API server; the web interface cannot start
```

Once `auth_enabled` is on:

- Browsers navigating to a page are redirected to `/login`.
- API clients get `401` with a JSON body, never a redirect into HTML.
- The session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever the
  request arrived over TLS — directly, or through a proxy that sets
  `X-Forwarded-Proto: https`.
- Requests that change state and rely on the cookie are refused (`403`) when
  their `Origin` or `Referer` names another site. A proxy that changes the
  host must pass the browser's host in `X-Forwarded-Host`, or list the public
  origin in `[api.cors].allowed_origins`.
- Five failed logins for one account from one address, or twenty from one
  address in total, within 15 minutes lock that address out (`429`) for the
  rest of the window. This applies to the login form and to HTTP Basic auth.

That last point matters if you terminate TLS at a proxy: **set
`X-Forwarded-Proto`**, otherwise the cookie is issued without `Secure` and can
be sent over a plaintext connection.

---

### Never run the admin API without authentication off-host

`[api].auth_enabled` defaults to **true** since v0.2.0. If you turn it off
while the web service is bound to anything but loopback (the shipped
`docker-compose` binds `0.0.0.0`), anyone who can reach the port can:

- read any queued message — full content and headers
- flush queues (delete mail) and requeue
- read and rewrite server configuration
- send mail through the test endpoint

There is no read-only mode. Treat the API/web port exactly as you would a
root shell on the mail server.

The server now logs a `SECURITY:` warning at startup when it binds to anything
other than loopback with auth disabled — do not ignore it. Choose one of:

1. **Bind to loopback.** Set `[api].listen_addr = "127.0.0.1:8025"` (or the
   `--listen` flag) and reach it via SSH tunnel or a co-located proxy. This is
   the right default for most deployments.
2. **Keep authentication on** (the default) and provide an auth file
   (`[api].auth_file`). Required if the port is reachable by anyone you do not
   fully trust.
3. **Front it with an authenticating reverse proxy** (mTLS, OIDC, or basic
   auth over TLS) and bind the app to loopback behind it.

`config/dev.toml` turns auth off on purpose for a single-host demo. Do not
copy it into production.

### Inbound and outbound on one server

One Elemta can be both the MX for your domains and the outbound relay for
your users and apps:

```toml
hostname = "mail.example.com"
local_domains = ["example.com"]
# Apps on your own network may send without logging in. See "Relay" below
# before using "private".
allowed_relays = ["private"]

[server]
listen = ":25"                 # inbound (MX): anyone may deliver to local_domains
listen_submission = ":587"     # outbound: log in over STARTTLS, or be in allowed_relays

[delivery]
mode = "split"                 # local_domains -> mailbox server over LMTP, everything else -> the internet
host = "mailbox.internal"
port = 24
```

- **Port 25 (MX)** accepts mail for `local_domains` from anyone, refuses
  unknown mailboxes at RCPT, and relays for nobody who has not logged in or is
  not in `allowed_relays`.
- **Port 587 (submission)** refuses `MAIL FROM` until the client has logged in
  (over STARTTLS) unless it is in `allowed_relays`. Point mail clients and
  apps here.
- **`split` delivery** sends local mail to the mailbox server and everything
  else out to the recipient's MX, DKIM-signed if configured.

Ports below 1024 need the process to be allowed to bind them (run as root,
grant `CAP_NET_BIND_SERVICE`, or map 25→2525 and 587→2587 in the container
runtime, which is what the dev stack does).

### Relay

Only authenticated clients, loopback, and the networks in `allowed_relays` may
send to domains outside `local_domains`. `allowed_relays` takes IPs, CIDRs,
and the names `"private"` (RFC 1918, CGNAT, IPv6 ULA, link-local) and
`"loopback"`. Do not list a network your load
balancer or Kubernetes Service SNATs public traffic into: every client then
arrives from it. If you need the real client address behind a proxy, use one
that preserves it (`externalTrafficPolicy: Local`, host networking, or a
direct listener), not a broader `allowed_relays`. Check the startup line
`Relay without authentication allowed from` after every config change, and
keep `dev_mode = false` (it enables the XDEBUG command).

### TLS

- Provide real certificate and key paths; do not run STARTTLS-only in
  production without a valid chain.
- Certificate and key files replaced on disk (certbot, cert-manager) are
  served within about 30 seconds, with no restart. Replace both files before
  the old certificate expires; a pair that fails to load is logged and the
  previous certificate stays in use.
- Cipher-suite ordering is controlled by the Go runtime (server-side ordering
  preferences are ignored by modern Go); rely on the runtime's secure defaults
  rather than trying to pin an order.

---

## 5) Content scanning

Antivirus and antispam are plugins. Enable the ones you run, and give them
addresses — the defaults assume `localhost`, which is wrong wherever the
scanners are separate containers or hosts.

```toml
[antivirus]
enabled = true
reject_on_failure = false

[antivirus.clamav]
enabled = true
address = "clamav.internal:3310"
timeout = 30
scan_limit = 26214400

[antispam]
enabled = true
reject_on_spam = false

[antispam.rspamd]
enabled = true
address = "http://rspamd.internal:11333"
timeout = 30
threshold = 6.0
```

Both `[antivirus].enabled` and `[antivirus.clamav].enabled` must be true; the
section gate and the per-scanner gate are both honoured.

### What the settings mean

- **`reject_on_failure`** — a scanner that cannot be reached delivers the
  message unscanned rather than refusing it. Leave it `false` unless you would
  rather lose mail than accept it unscanned; a scanner outage becomes a mail
  outage otherwise.
- **`reject_on_spam`** — the engine decides what is spam against its own
  threshold; this decides whether that verdict refuses the message. With it
  `false`, spam is delivered carrying `X-Spam-*` headers for downstream
  filtering. A virus verdict always refuses, regardless.
- **`scan_limit`** — how much of a message is sent to the scanner. Messages are
  streamed from the spool, so this bounds scanner work rather than memory.

If no scanner is reachable, the server logs a warning at startup and delivers
mail unscanned:

```
No antivirus scanner is available; messages will be delivered unscanned for viruses
```

Treat that line as an alert. Silence there previously looked identical to
working scanners.

### Latency

Scanning costs a network round trip per message per engine, and the two run
concurrently. Rspamd's optional lookups can dominate that:

- `fuzzy_check` queries rspamd.com over UDP for every message. Measured on a
  development stack it added roughly 4.3 seconds to about 5% of messages, cut
  throughput by more than half, and made it swing eightfold between runs.
- DNS blocklists (`rbl`, `surbl`) behave badly against a resolver that answers
  for names which should not exist — rspamd cannot then tell a working
  blocklist from a broken one.

Both are genuinely useful against bulk mail. Keep them if you want them, but
size for the latency and make sure Rspamd has a resolver that returns NXDOMAIN
properly. The development stack disables them for reproducibility, via
`docker/rspamd/override.d/`; those overrides are **not** intended for
production.

---

## 6) Upgrades and rollback

### Upgrade

1. Merge to `main` and let Docker Build push the image.
2. Run Deploy for `staging`, then check it.
3. Run Deploy for `production` with the same tag.

The deploy script treats an upgrade as healthy only when the `elemta` and
`elemta-admin` containers both report healthy and the MX port on the host
answers with a `220` banner, within 6 minutes (`HEALTH_TIMEOUT`).

### Rollback

This happens automatically: if the new tag does not start, or is not healthy
in time, the script puts the previous tag back in `.env`, brings it up, and
the workflow fails with both containers' recent logs in its output. There is
nothing to roll back to on the first deploy, so a failed first deploy is
left running for inspection.

To roll back by hand later, run Deploy with the earlier commit SHA as the
tag. Keep the queue backend setting unchanged unless the rollback
specifically requires switching backend, and re-check `/api/queue/storage`
and `/api/health` afterwards.

---

## 7) Queue backend caveat

Changing `queue.backend` does **not** migrate existing queued messages automatically.

Operational switching steps are documented in:

- [Queue Backend Runbook](queue-backend-runbook.md)
