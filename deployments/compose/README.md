# Docker Compose stacks

**The dev stack has moved to Kubernetes** (`make install-dev*`, see
[deployments/kubernetes](../kubernetes/README.md)); the `make` targets no longer
use `docker-compose.yml`. It stays here for the overlays below that have not
moved yet (mail-auth lab, ELK, multinode, monitoring), and is deleted when the
last of them does. `docker-compose.prod.yml` is still how production deploys.

| File | What it is | How to run |
|---|---|---|
| `docker-compose.yml` | Dev stack: Elemta, dashboard, caching resolver, Dovecot, LDAP, Valkey, LMTP sink, and optionally ClamAV, Rspamd, Roundcube | `make install-dev`, `make install-dev-full` |
| `docker-compose.prod.yml` | Production stack, run from the ghcr.io image | Deploy workflow; see [Production Deployment](../../docs/production-deployment.md) |
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
| 9080 | Prometheus metrics (container port 8080) |
| 11334 | Rspamd web UI (full stack) |
| 1389 / 1636 | LDAP / LDAPS |
| 14143 | IMAP (Dovecot) |
| 2424 | LMTP (Dovecot) |
| 4190 | ManageSieve |
| 6379 | Valkey |

All services share `elemta_network`, which has a fixed subnet
(10.253.53.0/24) so the caching resolver `elemta-dns` has a stable address.
After pulling a change to it, run `make down` once to recreate the network.
