# Releasing Elemta

This document describes how to cut a release of Elemta. The repository
currently has no git tags — this process starts with **v0.1.0** as the
first proposed release.

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

   `VERSION` is the pushed tag (e.g. `v0.1.0`), taken from `GITHUB_REF`. This
   stamps `internal/version.Version` (see
   [`internal/version/version.go`](../internal/version/version.go)) so both
   binaries report the correct release version at runtime instead of the
   `0.1.0-dev` placeholder baked into source.

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
   `## v0.1.0 (2026-07-09)`.
3. Commit the changelog update on `main`.
4. Tag the commit and push the tag:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

5. Watch the `Release` workflow run in GitHub Actions. On success, a draft
   is skipped — the release is published directly (`draft: false`) as
   `prerelease: false` unless you edit `release.yml` for a pre-release
   cadence (e.g. `v0.2.0-rc.1`, which would still match `v*.*.*`).
6. Sanity-check the published release: download at least one tarball and
   confirm `elemta-cli` (or `elemta`) reports the expected version.

## First release: v0.1.0

`internal/version.Version` is already `0.1.0-dev` in source, and this is a
reasonable, low-risk first tag: `v0.1.0`. Nothing about the release
workflow requires any code changes beyond what's already in place — cutting
`v0.1.0` only requires the manual steps above.

## Notes / non-goals

- No git tags exist yet in this repository. This document does not create
  one; tagging is a manual, deliberate action by a maintainer.
- Docker image publishing is handled separately by
  [`.github/workflows/build.yml`](../.github/workflows/build.yml) (pushes
  `:latest` and `:<sha>` to GHCR on every push to `main`) and is out of
  scope for the tag-triggered release workflow described here.
