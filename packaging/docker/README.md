# Docker-based Package Smoke Tests

These scripts are for **basic native package validation inside containers**.

This is useful for catching:

- broken RPM/DEB metadata
- missing packaged files
- bad install script behavior
- wrong ownership/directory layout

This is **not** a replacement for testing on real VMs/hosts with full `systemd`, journald, SELinux, and privileged port behavior.

## Example targets

- `rockylinux:9`
- `debian:12`
- `ubuntu:24.04`

## Example usage

```bash
./packaging/docker/test-package-install.sh rockylinux:9 dist/elemta_0.1.0_x86_64.rpm
./packaging/docker/test-package-install.sh debian:12 dist/elemta_0.1.0_amd64.deb
```
