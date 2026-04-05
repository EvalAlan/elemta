# Contributing to Elemta

Thanks for contributing.

## Development setup

```bash
git clone https://github.com/busybox42/elemta.git
cd elemta
make install-dev
```

## Branching and commits

- Create a focused branch per change.
- Use conventional commit style where practical (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- Keep commits atomic and reviewable.

## Required checks before PR

Run at minimum:

```bash
make test
make lint
```

For queue/backend or concurrency changes, also run:

```bash
go test ./internal/queue/... -race
go test ./internal/smtp -race -run 'TestHandleUnknown|TestCommandSequencing|TestConnectionDraining'
```

If behavior changed, update docs in the same PR.

## Pull request checklist

- [ ] Tests added/updated for behavior changes
- [ ] Relevant docs updated
- [ ] No unrelated refactors mixed in
- [ ] Security-sensitive changes called out in PR description
- [ ] Config changes include migration/rollback notes (if applicable)

## Reporting security issues

Do **not** open public issues for sensitive vulnerabilities.

See [SECURITY.md](SECURITY.md).

## Code style

- Prefer clear, explicit code over cleverness.
- Avoid hidden side effects.
- Keep API and config compatibility in mind.
- If removing behavior, document it and provide migration guidance.
