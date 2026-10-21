# Production: the full stack on one host with Compose

This runs everything a mail domain needs on one Linux host: the MTA (SMTP 25
and submission 587), the mailbox service (IMAP, POP3, LMTP, Sieve) with two
replicas behind HAProxy, Postgres, the directory, the webmail with calendar
and contacts, the admin dashboard, spam and virus scanning, and Caddy for
HTTPS and the certificate. It is the stack the development server runs, on the
release images.

Three Compose files, applied in this order:

| File | What it adds |
|---|---|
| `docker-compose.yml` | Every service and how they connect |
| `docker-compose.cloud.yml` | Internet-facing: public ports, everything else on loopback, Caddy, Let's Encrypt, no demo data |
| `docker-compose.release.yml` | Release images from ghcr.io, third-party images pinned by digest, container hardening |

`scripts/cloud-deploy.sh` renders the configuration for your domain, creates
the service credentials and the DKIM key, sets up the directory and the
certificate, and starts the stack with all three when `ELEMTA_TAG` is set.

(`docker-compose.prod.yml` is a different, smaller thing: the MTA alone,
relaying to mailboxes elsewhere. See [production-deployment.md](production-deployment.md).)

## Host

- Linux with Docker Engine and the Compose plugin; 4 GB of memory is enough
  for a small organisation (ClamAV alone takes 1–2 GB), 2+ cores, disk for
  mail plus backups.
- A public IPv4 address with **reverse DNS** set to the mail host name, and
  outbound port 25 allowed by the provider.
- Inbound 25, 587, 993, 143, 110, 80 and 443 open. Docker publishes ports
  past firewalld/ufw, so everything that must stay private is bound to
  127.0.0.1 by the compose files rather than relying on the host firewall.
- The user that deploys is in the `docker` group and can `sudo` (for the
  DKIM key's owner and the certificate-sync timer).

## Installing

```sh
git clone https://github.com/EvalAlan/elemta.git && cd elemta
git checkout v0.5.3                     # the scripts and compose files of the release
mkdir -p deployments/compose/.secrets && chmod 700 deployments/compose/.secrets
cat > deployments/compose/.secrets/cloud.env <<'EOF'
MAIL_DOMAIN=mail.example.org          # host name = mail domain
ELEMTA_TAG=v0.5.3                     # run the release images
DKIM_SELECTOR=s2026
ELEMTA_ADMIN_ALLOWED_IP=203.0.113.7   # who may reach the dashboard on :8025
ELEMTA_ADMIN_BIND_IP=0.0.0.0          # omit to keep the dashboard on loopback (SSH tunnel)
EOF
scripts/cloud-deploy.sh
```

It prints the DNS records to publish (SPF, DKIM, SRV for mail apps). Add an
MX record pointing at the host and a DMARC record of your choosing. Then
create the first accounts as described in [cloud-dev.md](cloud-dev.md)
("Accounts") and [mail-administration.md](mail-administration.md).

Run the script again after changing `cloud.env`; it is idempotent. It
re-renders the configuration, which replaces settings saved in the
dashboard; make lasting changes in the script's rendering instead.

## Backups

```sh
scripts/backup.sh /var/backups/elemta/$(date +%F-%H%M)
scripts/restore-drill.sh /var/backups/elemta/<that directory>
```

A backup holds the mailbox (Postgres dump and message bodies), the
directory, the MTA queue and runtime configuration, and `.secrets` (TLS and
DKIM keys, service passwords and the key that encrypts users' two-step
verification). Without the secrets a restore loses everyone's two-step
setup. Set `BACKUP_AGE_RECIPIENT` to an [age](https://age-encryption.org)
public key to encrypt them in the backup.

It runs against the live stack; nothing stops. Schedule it (a systemd timer
or cron, daily or more often), copy each backup off the host, and keep
`[maintenance] body_grace_hours` in the mailbox configuration longer than
the interval between backups.

`restore-drill.sh` proves a backup restores without touching the stack:
checksums, the mailbox restored into throwaway containers with every body
verified, and the directory loaded into a throwaway server. Run it on every
backup if you can, and certainly after any upgrade.

## Restoring

```sh
scripts/restore.sh /var/backups/elemta/<directory> --confirm
```

It stops the MTA first, so mail arriving meanwhile waits at the sending
servers and is retried, then restores the mailbox, directory, queue and
configuration and starts everything again. On a new host: install Docker,
check out the backup's release, decrypt the secrets archive if it is
encrypted, and run it; with no `.secrets` yet it restores those first. Then
run `scripts/cloud-deploy.sh` once so Caddy fetches a certificate and the
renewal timer is installed.

Drilled on the development server: a backup restored over the live stack came
back with the same messages, flags and bodies (identical fingerprint), the
same directory, and every service healthy.

## Upgrades

```sh
scripts/backup.sh /var/backups/elemta/before-v0.6.0     # always
git fetch --tags && git checkout v0.6.0
sed -i 's/^ELEMTA_TAG=.*/ELEMTA_TAG=v0.6.0/' deployments/compose/.secrets/cloud.env
scripts/cloud-deploy.sh
```

Read the release's upgrade notes in [CHANGELOG.md](../CHANGELOG.md) first.
Schema changes apply on start and are additive.

To roll with less disruption than recreating everything at once, pull and
recreate one service at a time, waiting for each to be healthy: the
mailbox replicas (`elemta-mailbox-a`, then `-b`; clients reconnect to the
other), then `elemta`, `elemta-webmail` and `elemta-web`:

```sh
C="docker compose --env-file deployments/compose/.secrets/cloud.env \
  -f deployments/compose/docker-compose.yml -f deployments/compose/docker-compose.cloud.yml \
  -f deployments/compose/docker-compose.release.yml"
$C pull --ignore-buildable
for s in elemta-mailbox-a elemta-mailbox-b elemta elemta-webmail elemta-web; do
  $C up -d --no-deps $s   # then wait for: docker inspect -f '{{.State.Health.Status}}' <container>
done
$C up -d
```

**Rollback:** set `ELEMTA_TAG` back and do the same. A release that changed
the schema keeps working with the previous one's code, because changes are
additive; if a release says otherwise, restore the backup taken before it.

Drilled on the development server: the stack was rolled from locally built
images onto the release overlay one service at a time while an account sent
itself a numbered message every two seconds. Each mailbox replica was healthy
again in 7–8 s, the MTA in 14 s, webmail and dashboard in 8 s. All 146
messages arrived exactly once; one send was refused while the MTA restarted
and went through on its retry, as a mail app's would. Rolling back to the
previous images the same way took the same few seconds per service. The
drill also caught a real defect, now fixed: the webmail's shared
configuration checks the queue directory is writable, which a read-only
root filesystem refused.

## Hardening

What the overlay and the stack do:

- Release images are what CI built and tested for the tag. Third-party
  images are pinned by digest; update them deliberately, with a backup and
  a drill.
- Every container: `no-new-privileges`, memory and process limits, rotated
  logs. Elemta's own containers also run as uid 1001 with all capabilities
  dropped and a read-only root filesystem.
- Only mail and HTTPS ports are public. LDAP, Postgres, Valkey, Rspamd,
  ManageSieve, plaintext IMAP, LMTP and metrics are on loopback or the
  internal network. The dashboard is reachable only from
  `ELEMTA_ADMIN_ALLOWED_IP`, through Caddy, with its own login.
- TLS 1.2 and 1.3 only, forward-secret AEAD suites only, on every port
  (an nmap `ssl-enum-ciphers` scan of dev rates every port A). Public IMAP
  and POP3 never accept a password before TLS.
- Webmail and dashboard send a strict Content-Security-Policy, HSTS,
  `X-Frame-Options: DENY` and `nosniff`; sign-ins are throttled per address
  and per account; two-step verification can be required per class of
  service.
- CI runs gosec, govulncheck, dependency licence checks and the security
  gate on every push.

Known gaps:

- The directory image (`osixia/openldap`) is no longer maintained upstream
  and ships OpenLDAP 2.4.57. It is reachable only on the internal network
  and loopback, but it should be replaced with a maintained OpenLDAP image
  (or an external directory) in a coming release.
- One host is one failure domain. The mailbox replicas protect against a
  crashed process, not a lost host; the backups are the disaster plan.
- Rspamd and ClamAV run as root inside their containers (their images
  need it), without the read-only filesystem the Elemta containers have.
