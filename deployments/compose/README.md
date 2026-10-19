# Docker Compose stacks

Run these through `make` from the repository root where a target exists; the
targets set the environment the files expect.

| File | What it is | How to run |
|---|---|---|
| `docker-compose.yml` | Dev stack: Elemta, admin console, mailbox service (two replicas, HAProxy, Postgres), webmail, caching resolver, LDAP, Valkey, and optionally ClamAV, Rspamd, Roundcube and an LMTP sink | `make install-dev`, `make install-dev-full` |
| `docker-compose.cloud.yml` | Overlay: the dev stack on one internet-facing server, with Let's Encrypt and only the public mail ports | `scripts/cloud-deploy.sh`; see [Cloud dev server](../../docs/cloud-dev.md) |
| `docker-compose.prod.yml` | Production MTA and admin console, run from the ghcr.io image | Deploy workflow; see [Production Deployment](../../docs/production-deployment.md) |
| `docker-compose-mailauth.yml` | Overlay: DKIM signing / ARC sealing lab with its own DNS zone | `make install-dev-mailauth` |
| `docker-compose-elk.yml` | Overlay: Filebeat, Elasticsearch and Kibana log shipping | `make elk-up` |
| `docker-compose-full.yml` | Older ELK overlay used by `scripts/setup-elk.sh` | `scripts/setup-elk.sh` |
| `docker-compose-multinode.yml` | Overlay: three SMTP nodes sharing Valkey rate limits | `docker compose -f docker-compose.yml -f docker-compose-multinode.yml up -d` |
| `docker-compose-monitoring.yml` | Prometheus, Grafana, Alertmanager | `docker compose -f docker-compose-monitoring.yml up -d` |
| `docker-compose-cli.yml`, `docker-compose-test.yml` | CLI and test helpers | by hand |

## Dev stack ports (host side)

| Port | Service |
|---|---|
| 2525 | SMTP (MX) |
| 2587 | Submission |
| 8025 | Dashboard and API |
| 8026 | Roundcube (full stack) |
| 8027 | Webmail |
| 9080 | Prometheus metrics (container port 8080) |
| 11334 | Rspamd web UI (full stack) |
| 1389 / 1636 | LDAP / LDAPS |
| 993 | IMAPS (mailbox service) |
| 14143 | IMAP, plaintext, internal (mailbox service) |
| 143 / 110 | IMAP STARTTLS / POP3, loopback only |
| 2424 | LMTP (mailbox service) |
| 4190 | ManageSieve (mailbox service) |
| 6379 | Valkey |

All services share `elemta_network`, which has a fixed subnet
(10.253.53.0/24) so the caching resolver `elemta-dns` has a stable address.
After pulling a change to it, run `make down` once to recreate the network.
