# Elemta Documentation

Maintained docs for the current codebase. If behaviour and docs disagree,
update the docs in the same PR as the code change. Design reasoning and known
traps live in [HANDOFF.md](../HANDOFF.md); release-by-release changes in the
[CHANGELOG](../CHANGELOG.md).

## Start here

- [Architecture](architecture.md): how the parts fit together, with diagrams of the Docker Compose, cloud and Kubernetes layouts
- [User Guide](user-guide.md): webmail, mail apps, two-step verification and app passwords
- [Installation](installation.md)
- [Configuration](configuration.md)
- [CLI Reference](cli.md)

## Mail server (MTA)

- [SMTP Server](smtp_server.md)
- [DKIM Signing](dkim-signing.md)
- [Rate Limiting](rate-limiting.md)
- [Plugin System](plugins.md)

## Mailbox service

- [Mailbox Service](mailbox-service.md): IMAP, POP3, LMTP, Sieve and ManageSieve, storage, backups
- [Mailbox Engine Architecture](mailbox-engine-architecture.md): design and scaling targets

## Webmail

- [Calendar and contacts sync (CalDAV, CardDAV)](webmail-sync.md)
- [Password recovery](webmail-recovery.md)
- [Object storage for calendar, contacts and settings](webmail-object-storage.md)

## Accounts and administration

- [Mail Administration](mail-administration.md): domains, accounts, aliases, LDAP service accounts, admin API

## Queue and delivery

- [Queue Management](queue_management.md)
- [Queue Backend Runbook (file, sqlite, postgres)](queue-backend-runbook.md)
- [API Reference](api-reference.md)

## Operations

- [Cloud Dev Server](cloud-dev.md): the whole stack on one internet-facing host
- [Cloud Stress Testing](cloud-stress-testing.md)
- [Production Deployment](production-deployment.md)
- [Production Readiness: honest assessment and limitations](production-readiness.md)
- [Testing](testing.md)
- [Troubleshooting](troubleshooting.md)
- [Releasing](releasing.md)

## Additional topics

- [Logging](logging.md)
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
