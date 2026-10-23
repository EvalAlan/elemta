# Running more than one of everything

Every Elemta service can run as several containers behind a load balancer,
so a crashed or restarting container doesn't stop mail and each tier can be
scaled to its load. This page covers Docker Compose on one host. A
Kubernetes deployment, which also survives losing a host, follows the same
design.

## What runs how

| Tier | Instances | In front | Shared state |
|---|---|---|---|
| MTA (`elemta`) | any number | `elemta-edge` (HAProxy), ports 25 and 587, PROXY protocol | the queue, in Postgres |
| Mailbox servers (`elemta-mailbox-server`) | any number (2 by default, also without the overlay) | `elemta-mailbox` (HAProxy), PROXY protocol on the public ports | Postgres, message bodies |
| Webmail | any number | Caddy, a browser kept on one | sessions in Valkey |
| Dashboard | any number | Caddy | sessions in Valkey (`[api] session_store`) |
| Directory | 2 replicating nodes | `elemta-ldap` (HAProxy) | multi-provider replication |
| Postgres, Valkey | one each, for now | | |

Load balancers pass each client's own address to the MTA and the mailbox
servers with the PROXY protocol (`[server] proxy_protocol_from`), so spam and
blocklist checks, rate limits, relay rules and sign-in throttling still see
the client, not the balancer.

## Turning it on

The scaling overlay goes last, after the cloud and release overlays:

```sh
cd deployments/compose
C="docker compose --env-file .secrets/cloud.env -f docker-compose.yml \
  -f docker-compose.cloud.yml -f docker-compose.release.yml -f docker-compose.scale.yml"
export ELEMTA_LDAP_IMAGE=ghcr.io/evalalan/elemta-ldap:$ELEMTA_TAG
$C up -d --remove-orphans
```

In `.secrets/cloud.env`, set `ELEMTA_SMTP_PORT=25` and
`ELEMTA_SUBMISSION_PORT=587` so the edge balancer publishes the standard
ports (they default to 2525 and 2587 for a development stack).
`scripts/dev-secrets.sh` writes `.secrets/queue.env`, which points the MTAs
at the shared queue.

Before switching, let the MTA's queue empty (Queues in the dashboard): the
file queue isn't moved into Postgres.

The directory's first node keeps the existing directory's volumes; the
second starts empty and fills itself from the first. The schema, password and
service-account scripts apply configuration to every node.

## Scaling up and down

```sh
$C up -d --no-deps --scale elemta=3 --scale elemta-webmail=3 \
    --scale elemta-web=2 --scale elemta-mailbox-server=4
```

Or set the defaults in `.secrets/cloud.env`: `ELEMTA_MTA_REPLICAS`,
`ELEMTA_WEBMAIL_REPLICAS`, `ELEMTA_WEB_REPLICAS`, `ELEMTA_MAILBOX_REPLICAS`.
The load balancers find containers by name and follow scaling within a few
seconds (up to 20 MTAs and 10 mailbox servers per balancer).

Scaling the MTA down is safe at any time: messages are claimed from the
shared queue with 15-minute leases, so one a stopped container was holding is
taken up by another when its lease runs out.

## Updating without downtime

```sh
$C pull --ignore-buildable
ELEMTA_SCALE=1 scripts/rolling-update.sh
```

For each service it starts as many new containers as are running, waits for
them to be healthy, and removes the old ones one at a time.

## Valkey addresses

Every Valkey address setting (`VALKEY_ADDR`, `[api].valkey_addr`, the
webmail session store, rate limiting) takes either a plain `host:port`, one
server, or a URL. A URL with `master_set` names Sentinels instead, and the
services follow the primary when Sentinel fails it over:

```
valkey://valkey-sentinel:26379?master_set=elemta
valkey://:password@s1:26379?addr=s2:26379&addr=s3:26379&master_set=elemta
```

A password in the URL is the primary's. The Sentinels are reached without one.

## What one host can't do

All of this runs on one host, so it survives containers failing and being
replaced, not the host itself. Postgres and Valkey still run once. Running
across hosts, with Postgres and Valkey failing over, is the Kubernetes
deployment's job; backups ([production-compose.md](production-compose.md))
remain the plan for losing the host.
