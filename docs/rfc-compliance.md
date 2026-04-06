# RFC Compliance (Current Snapshot)

This is a practical status summary, not a line-by-line formal conformance claim.

## Core coverage

Elemta implements the primary SMTP transaction flow and common modern extensions used in the codebase/test suite.

### Implemented/advertised capabilities (current)

- SMTP core transaction commands (`HELO/EHLO`, `MAIL`, `RCPT`, `DATA`, `RSET`, `NOOP`, `QUIT`)
- CHUNKING/BDAT path
- PIPELINING path
- STARTTLS path (when configured)
- AUTH path (when configured)
- DSN and REQUIRETLS parsing paths

## Partial/deferred areas

The code includes parsing/support scaffolding for some advanced features where full end-to-end enforcement or generation remains partial in current runtime behavior.

Typical examples include:

- full DSN notification generation lifecycle
- full outbound REQUIRETLS enforcement lifecycle
- full SMTPUTF8/i18n coverage edge cases

## Verification sources

Use tests and runtime checks as authoritative proof points:

```bash
make test
make test-race-smoke
```

And inspect protocol behavior directly with SMTP session tests against a running instance.

## Contributor rule

When changing protocol behavior:

1. update tests
2. update docs
3. call out compatibility/risk in PR notes
