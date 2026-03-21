# Packaging Assets

This directory contains native packaging assets for Elemta.

Current direction:

- RPM and DEB packages
- standard FHS layout
- no `/opt`
- native installs are first-class

Planned initial toolchain:

- GoReleaser
- nfpm

## Layout

- `systemd/` - service unit, sysusers, and tmpfiles assets
- `config/` - packaged default configuration skeletons
- `config/conf.d/` - example drop-in configuration fragments
- `scripts/` - package/install smoke test helpers
- `docker/` - Docker-based package validation helpers

## Notes

These assets are intentionally early-stage scaffolding. The canonical layout and service model are defined in:

- `docs/native-install-spec-v1.md`
