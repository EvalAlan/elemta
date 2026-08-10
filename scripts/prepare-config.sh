#!/bin/sh
# Prepare the runtime configuration and print its path.
#
# The image ships a configuration template and the compose stack bind-mounts the
# repository's config over it read-only, so neither is writable by the service.
# Everything the web UI saves — plugin toggles, scanner settings, blocklist
# zones — therefore used to be written to a per-container copy under /tmp. That
# had two consequences worth stating plainly:
#
#   1. Nothing survived a restart. A toggle flipped in the UI was gone at the
#      next `docker compose up`.
#   2. The SMTP node and the web node each had their own copy, so a change made
#      in the UI could never reach the server that enforces it — even though the
#      UI correctly said "restart required".
#
# So the runtime configuration lives on a volume both services share. The
# read-only mount stays as the template it always was; this seeds from it once
# and then leaves it alone, because re-copying on every start would overwrite
# whatever the operator had just saved.
#
# Consequence to be aware of: once the volume exists, editing the repository's
# config/elemta.toml no longer changes the running stack. Set
# ELEMTA_CONFIG_RESEED=true to take the template again, discarding what the UI
# has saved.

set -eu

RUNTIME_DIR="${ELEMTA_RUNTIME_CONFIG_DIR:-/app/runtime-config}"
RUNTIME_CONFIG="$RUNTIME_DIR/elemta.toml"

mkdir -p "$RUNTIME_DIR" 2>/dev/null || true

if [ "${ELEMTA_CONFIG_RESEED:-}" = "true" ]; then
    rm -f "$RUNTIME_CONFIG"
fi

if [ ! -f "$RUNTIME_CONFIG" ]; then
    for candidate in /app/config/elemta-generated.toml /app/config/elemta.toml; do
        [ -f "$candidate" ] || continue

        # Seed atomically. Both services start together and would otherwise race
        # to create the same file; ln fails when the target already exists, so
        # the loser simply drops its copy.
        tmp="$RUNTIME_CONFIG.$$"
        if cp "$candidate" "$tmp" 2>/dev/null; then
            chmod 600 "$tmp" 2>/dev/null || true
            ln "$tmp" "$RUNTIME_CONFIG" 2>/dev/null || true
            rm -f "$tmp"
        fi
        [ -f "$RUNTIME_CONFIG" ] && break
    done
fi

if [ ! -f "$RUNTIME_CONFIG" ]; then
    echo "prepare-config: no configuration found to seed from" >&2
    exit 1
fi

# The server refuses a configuration that is group- or world-readable, since it
# can hold credentials. A bind-mounted template carries the host's permissions,
# so tighten whatever we ended up with rather than assuming.
chmod 600 "$RUNTIME_CONFIG" 2>/dev/null || true

echo "$RUNTIME_CONFIG"
