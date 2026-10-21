# Releasing Elemta

This document describes how to cut a release of Elemta. The first tagged
release is **v0.5.0**: v0.3.0 and v0.4.0 were described in the changelog but
never tagged, so tags continue that numbering.

## Tagging convention

Releases use [semantic versioning](https://semver.org/) with a `v` prefix:

```
vMAJOR.MINOR.PATCH
```

Examples: `v0.1.0`, `v0.2.0`, `v0.2.1`, `v1.0.0`.

- `MAJOR` — breaking changes to config format, CLI behavior, or protocol
  handling that require operator action.
- `MINOR` — new features/backwards-compatible behavior changes.
- `PATCH` — bug fixes only.

Pre-1.0 (`v0.x.y`), minor version bumps may still include breaking changes;
call these out clearly in the release notes.

## What triggers a release

Pushing a tag matching `v*.*.*` triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml). Nothing
else in CI creates GitHub Releases.

## What the release workflow does

1. **Build** — for each of `linux/amd64` and `linux/arm64`, builds both
   binaries with `CGO_ENABLED=0`:
   - `cmd/elemta` (the SMTP server) → `elemta`
   - `cmd/elemta-cli` (the CLI) → `elemta-cli`

   Both binaries are built with:

   ```
   go build -trimpath -ldflags "-s -w -X github.com/EvalAlan/elemta/internal/version.Version=${VERSION}"
   ```

   `VERSION` is the pushed tag (e.g. `v0.5.0`), taken from `GITHUB_REF`. This
   stamps `internal/version.Version` (see
   [`internal/version/version.go`](../internal/version/version.go)) so both
   binaries report the correct release version at runtime instead of the
   `-dev` placeholder baked into source (`0.5.0-dev`; bump it to the next
   minor after tagging).

2. **Package** — each arch's pair of binaries is packaged into
   `elemta-<version>-linux-<arch>.tar.gz`.

3. **Release** — a GitHub Release is created for the tag using
   [`softprops/action-gh-release`](https://github.com/softprops/action-gh-release)
   with the tarballs attached and GitHub-generated release notes
   (`generate_release_notes: true`, i.e. the auto-generated "Full Changelog"
   + merged-PR list based on the previous tag).

The workflow does **not** build Docker images or macOS/Windows binaries.
Only linux/amd64 and linux/arm64 are covered today; expand the build matrix
in `release.yml` if/when other platforms are needed.

## Cutting a release (manual steps)

1. Make sure `main` is green (tests, lint, security gate all passing).
2. Update [`CHANGELOG.md`](../CHANGELOG.md) with a dated entry summarizing
   what's in the release. The existing changelog is narrative rather than
   strictly "Keep a Changelog"-formatted — follow the existing style, but
   include the version number in the heading going forward, e.g.
   `## v0.5.0 (2026-10-20)`.
3. Commit the changelog update on `main`.
4. Tag the commit and push the tag:

   ```bash
   git tag -a v0.5.0 -m "v0.5.0"
   git push origin v0.5.0
   ```

5. Watch the `Release` workflow run in GitHub Actions. On success, a draft
   is skipped — the release is published directly (`draft: false`) as
   `prerelease: false` unless you edit `release.yml` for a pre-release
   cadence (e.g. `v0.2.0-rc.1`, which would still match `v*.*.*`).
6. Sanity-check the published release: download at least one tarball and
   confirm `elemta-cli` (or `elemta`) reports the expected version.

## Container images

The same tag also runs [`.github/workflows/build.yml`](../.github/workflows/build.yml),
which publishes `ghcr.io/evalalan/elemta:vX.Y.Z`,
`ghcr.io/evalalan/elemta-mailbox:vX.Y.Z` (version stamped in) and
`ghcr.io/evalalan/elemta-ldap:vX.Y.Z`, the directory. Pushes
to `main` publish `:latest` and `:<commit sha>`. The production overlay
(`docker-compose.release.yml`, see [production-compose.md](production-compose.md))
runs these by `ELEMTA_TAG`.

Before tagging, run the upgrade drill from [production-compose.md](production-compose.md)
against the commit's images (`ELEMTA_TAG=<sha>`): the release images are
the same build.
