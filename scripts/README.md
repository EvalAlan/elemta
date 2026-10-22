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
| `ssl/` | Let's Encrypt setup, test, monitor and troubleshooting scripts |
| `test/` | `run-all-tests.sh`, `run-datasource-tests.sh` |
| `monitoring/` | Monitoring stack setup and `verify-monitoring-stack.sh` |
| `queue/` | Queue inspection and simulation helpers |
| `load-testing/` | Load and security-event generators |
| `debug/` | `debug-email.sh` |
| `docker/` | `docker-deploy.sh` |

## Other root-level scripts

- `elemta-api.sh`, `elemta-cli.sh` — API and CLI wrappers
- `ldap-mail-admin.sh`, `user-manager.sh` — LDAP user administration for the dev stack
- `setup-elk.sh`, `create-mta-index-patterns.sh`, `import-mta-dashboards.sh`,
  `populate-dashboards.sh`, `dashboard-keepalive.py` — ELK/Kibana helpers
- `build_plugins.sh` — build example plugins
- `deploy-and-test.sh`, `run.sh` — older one-shot dev wrappers
- `realistic-smtp-test.py`, `test-dashboard-population.py`, `mock-queue.py`, `api_server.py` — ad-hoc test helpers

## Prerequisites

Docker with Compose v2, Go (version in `go.mod`), OpenSSL, and Python 3 for
the `.py` scripts. SSL scripts need DNS control of the domain.

When adding a script, put it in the matching directory, give it a usage header,
and add it here.
