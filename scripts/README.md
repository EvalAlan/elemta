# Elemta Scripts

Utility scripts, grouped by directory. Most dev workflows are wrapped by `make`
targets (`make help`); prefer those where one exists. Each script's header
documents its usage.

## Used by the build and runtime

These are called by the Dockerfile, compose files or Makefile; change them
with care.

- `entrypoint.sh` — container entry point (runs as the unprivileged user)
- `prepare-config.sh` — seeds the runtime config volume and prints its path
- `configure_queue_backend.py`, `configure_plugins.py` — used by the
  `make install-dev*` targets
- `init-ldap-if-needed.sh`, `init-ldap-users.sh` — dev LDAP bootstrap
- `metrics_server.py` — mounted by `docker-compose-monitoring.yml`

## Directories

| Directory | Contents |
|---|---|
| `deploy/` | `remote-deploy.sh`, run on the target host by the Deploy workflow; see [Production Deployment](../docs/production-deployment.md) |
| `dev/` | Dev-stack tooling: rebuilds, benchmarks, stress corpus, Rspamd training, ELK dashboards, mail-auth lab ([README](dev/README.md)) |
| `ssl/` | Let's Encrypt setup, monitor and troubleshooting scripts |
| `monitoring/` | Monitoring stack setup and `verify-monitoring-stack.sh` |
| `queue/` | Queue inspection and simulation helpers |
| `debug/` | `debug-email.sh` |
| `docker/` | `docker-deploy.sh` |

## Other root-level scripts

- `elemta-api.sh`, `elemta-cli.sh` — API and CLI wrappers
- `ldap-mail-admin.sh`, `user-manager.sh` — LDAP user administration for the dev stack
- `setup-elk.sh`, `create-mta-index-patterns.sh`, `import-mta-dashboards.sh`,
  `dashboard-keepalive.py` — ELK/Kibana helpers
- `build_plugins.sh` — build example plugins
- `run.sh` — older one-shot dev wrapper
- `mock-queue.py`, `api_server.py` — ad-hoc dev helpers

Load, stress and end-to-end tests against a running stack are in the
separate elemta-tests repository.

## Prerequisites

Docker with Compose v2, Go (version in `go.mod`), OpenSSL, and Python 3 for
the `.py` scripts. SSL scripts need DNS control of the domain.

When adding a script, put it in the matching directory, give it a usage header,
and add it here.
