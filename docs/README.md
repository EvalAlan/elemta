# Elemta Documentation

Maintained docs for the current codebase. If behaviour and docs disagree,
update the docs in the same PR as the code change. Design reasoning and known
traps live in [HANDOFF.md](../HANDOFF.md); release-by-release changes in the
[CHANGELOG](../CHANGELOG.md).

## Start here

- [Installation](installation.md)
- [Configuration](configuration.md)
- [SMTP Server](smtp_server.md)
- [CLI Reference](cli.md)

## Queue and delivery

- [Queue Management](queue_management.md)
- [Queue Backend Runbook (file, sqlite, postgres)](queue-backend-runbook.md)
- [DKIM Signing](dkim-signing.md)
- [API Reference](api-reference.md)

## Operations

- [Production Deployment](production-deployment.md)
- [Production Readiness: honest assessment and limitations](production-readiness.md)
- [Testing](testing.md)
- [Troubleshooting](troubleshooting.md)
- [Releasing](releasing.md)

## Additional topics

- [Logging](logging.md)
- [Rate Limiting](rate-limiting.md)
- [Plugin System](plugins.md)
- [Docker Compose stacks](../deployments/compose/README.md)
- [Monitoring](monitoring/README.md)

## Proposals and design notes

- [Native Install Spec v1](native-install-spec-v1.md): proposed RPM/DEB layout, not shipped
- [Disk spooling of message data](plans/data-path-disk-spooling.md): completed plan, kept for its reasoning

## Governance

- [Contributing Guide](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Support](../SUPPORT.md)
