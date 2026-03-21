#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64)
    PKG_ARCH="amd64"
    RPM_ARCH="amd64"
    ;;
  aarch64|arm64)
    PKG_ARCH="arm64"
    RPM_ARCH="arm64"
    ;;
  *)
    echo "unsupported host arch: $ARCH_RAW" >&2
    exit 1
    ;;
esac

if [[ -d dist ]]; then
  docker run --rm \
    -v "$ROOT":/workspace \
    -w /workspace \
    alpine:3.20 \
    /bin/sh -lc 'chown -R $(stat -c %u /workspace):$(stat -c %g /workspace) dist 2>/dev/null || true; rm -rf dist'
fi

mkdir -p "$ROOT/.tmp/goreleaser-home" "$ROOT/.tmp/gocache"

docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp/goreleaser-home \
  -e GOCACHE=/tmp/gocache \
  -v "$ROOT":/workspace \
  -v "$ROOT/.tmp/goreleaser-home":/tmp/goreleaser-home \
  -v "$ROOT/.tmp/gocache":/tmp/gocache \
  -w /workspace \
  goreleaser/goreleaser:latest \
  release --snapshot --clean --skip=publish

DEB_FILE="$(find dist -maxdepth 1 -type f -name "*_${PKG_ARCH}.deb" | head -n 1)"
RPM_FILE="$(find dist -maxdepth 1 -type f -name "*_${RPM_ARCH}.rpm" | head -n 1)"

if [[ -z "$DEB_FILE" || -z "$RPM_FILE" ]]; then
  echo "failed to locate built package artifacts" >&2
  exit 1
fi

./packaging/docker/test-package-install.sh debian:12 "$DEB_FILE"
./packaging/docker/test-package-install.sh rockylinux:9 "$RPM_FILE"
./packaging/docker/test-package-runtime.sh debian:12 "$DEB_FILE"
./packaging/docker/test-package-runtime.sh rockylinux:9 "$RPM_FILE"

echo "snapshot package build + smoke tests passed"
