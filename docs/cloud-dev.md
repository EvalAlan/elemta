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
`elemta-web` first, then `elemta-caddy`. Caddy serves
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
  other than 25, 80, 443, 587 and 993.
- **Swap.** A 2 GB swapfile, because ClamAV alone wants about 1.5 GB.

## Deploying

From a checkout on your workstation, send the committed tree to the server and
run the deploy script there:

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

Re-running the script replaces settings saved in the admin console with the
rendered configuration. Make lasting changes in the script.

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

## Accounts

The directory starts empty. Create the domain's accounts with the provision
command, which prompts for the password:

```
docker exec -it elemta-web /app/elemta -c /app/runtime-config/elemta.toml \
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

- IMAP: `<domain>`, port 993, SSL/TLS
- SMTP: `<domain>`, port 587, STARTTLS
- Username: the full address

## Stress testing

The [cloud stress runner](cloud-stress-testing.md) exercises verified SMTP,
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
