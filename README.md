![Elemta Logo](images/elemta.png)

# Elemta

Elemta is a high-performance SMTP server written in Go with a modular pipeline, queue management, API/web surfaces, and production-focused security controls.

## Highlights

- SMTP server with extensible processing pipeline
- Queue backends: `file` (default) and `sqlite` (opt-in)
- Built-in queue/API/web tooling for operational visibility
- Delivery/auth integrations (file, LDAP, SQL backends)
- Docker and Kubernetes deployment assets
- Prometheus/Grafana-ready metrics and health endpoints

## Quick Start

### 1) Local development (recommended)

```bash
git clone https://github.com/busybox42/elemta.git
cd elemta

# Minimal stack (fast)
make install-dev

# Full stack (clamav/rspamd/roundcube included)
# make install-dev-full
```

Useful commands:

```bash
make status
make logs-elemta
make test
make test-load
```

### 2) Run from source

```bash
go build -o build/elemta ./cmd/elemta
./build/elemta server --config ./config/elemta.toml
```

### 3) Docker Compose directly

```bash
docker compose -f deployments/compose/docker-compose.yml up -d
```

## Core Docs

- [Documentation index](docs/index.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Queue backend v1 design](docs/queue-db-backend-v1.md)
- [Queue backend operator runbook](docs/queue-backend-runbook.md)
- [Queue management](docs/queue_management.md)
- [Testing](docs/testing.md)
- [Production deployment](docs/production-deployment.md)
- [API reference](docs/api-reference.md)

## Security & Project Governance

- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Support](SUPPORT.md)
- [Roadmap](ROADMAP.md)

## Contributing

PRs are welcome. Before opening one:

1. Run tests and lint locally (`make test` and `make lint`)
2. Update docs when behavior/config changes
3. Keep changes focused and scoped

Full guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
