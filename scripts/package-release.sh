#!/usr/bin/env bash
# Package one architecture's release tarball. The Release workflow runs this,
# and it can be run by hand to see exactly what a release will contain.
#
# Usage: scripts/package-release.sh <version> <goarch> <bin-dir>
#
# <bin-dir> holds the built elemta and elemta-cli. The tarball is written to
# the current directory.
set -euo pipefail

version=${1:?version}
goarch=${2:?goarch}
bin_dir=${3:?directory holding the binaries}

root=$(cd "$(dirname "$0")/.." && pwd)
name="elemta-${version}-linux-${goarch}"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
out="$stage/$name"

mkdir -p "$out/third-party"
cp "$bin_dir/elemta" "$bin_dir/elemta-cli" "$out/"

# The binary embeds webmail, but the admin console reads these from disk and
# answers every page with a 404 without them.
cp -r "$root/web" "$out/web"

# Mode 600 because Elemta refuses a configuration other users can read.
install -m 600 "$root/packaging/release/elemta.toml" "$out/elemta.toml"
cp "$root/packaging/release/README.md" "$root/LICENSE" "$root/LICENSING.md" "$out/"

# MIT and BSD licenses require their text to travel with binaries, not only
# with source. Reading the modules actually linked keeps this list exact, and
# GOOS and GOARCH make it the right list for this build.
cd "$root"
GOOS=linux GOARCH=$goarch go list -deps \
    -f '{{with .Module}}{{.Path}} {{.Dir}}{{end}}' ./cmd/elemta ./cmd/elemta-cli |
    sort -u |
    while read -r module dir; do
        [ "$module" = "$(go list -m)" ] && continue
        found=0
        for file in "$dir"/LICEN[CS]E* "$dir"/COPYING* "$dir"/NOTICE*; do
            [ -f "$file" ] || continue
            mkdir -p "$out/third-party/$module"
            cp "$file" "$out/third-party/$module/"
            chmod u+w "$out/third-party/$module/$(basename "$file")"
            found=1
        done
        # A warning, not a failure: this runs after main has moved and the tag
        # exists, when a hard stop only blocks the release. The maintainer
        # reads the warning on the run.
        [ "$found" = 1 ] || echo "::warning::no license file found for $module"
    done

# In-tree copies that keep their own licenses, per LICENSING.md.
mkdir -p "$out/third-party/internal/imapfork" "$out/third-party/internal/sievefork"
cp internal/imapfork/LICENSE "$out/third-party/internal/imapfork/"
cp internal/sievefork/LICENSE "$out/third-party/internal/sievefork/"
cp internal/webmail/static/openpgp.LICENSE "$out/third-party/"

cd - >/dev/null
tar -czf "$name.tar.gz" -C "$stage" "$name"
echo "wrote $name.tar.gz"
