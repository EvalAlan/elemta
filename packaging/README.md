# Packaging

`release/` holds what the release tarball adds to the binaries:

- `elemta.toml`: the starter configuration, for trying Elemta on one machine
- `README.md`: the tarball's README

`scripts/package-release.sh` builds the tarball, and the Release workflow runs
it for each architecture (see `docs/releasing.md`). A test,
`internal/config/shipped_configs_test.go`, loads `release/elemta.toml` with
unknown keys treated as errors, so a renamed setting or a missing file fails
CI rather than the release.

Native RPM and DEB packages aren't built. The design for them is
`docs/native-install-spec-v1.md`; the earlier GoReleaser scaffolding was
removed because nothing built it and it had drifted from the code.
