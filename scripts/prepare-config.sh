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

# Reseed once per container, not once per start.
#
# ELEMTA_CONFIG_RESEED is set by `make install-dev*` to mean "this deploy is
# authoritative, take the template again". Compose bakes it into the container's
# environment, so it was still true on every subsequent `docker restart` — and
# each restart deleted the runtime config and re-copied the template, silently
# discarding everything the operator had saved in the web UI. A setting that
# survives until the next restart is worse than one that never saved at all,
# because it looks like it worked.
#
# The marker lives in the container's own writable layer, which is what makes it
# mean "this container instance". A recreate — what install-dev actually does —
# gets a fresh layer and reseeds. A plain restart finds the marker and leaves
# the operator's config alone.
#
# Not /tmp: that is mounted tmpfs in the shipped compose, so it is memory-backed
# and empty on every start, restart included. A marker there is always absent
# and the reseed fires every time — which is the bug this is fixing, reproduced
# by the fix for it. /app is writable by the service user and only its
# subdirectories are mounts.
RESEED_MARKER="/app/.config-reseeded"
if [ "${ELEMTA_CONFIG_RESEED:-}" = "true" ] && [ ! -f "$RESEED_MARKER" ]; then
    rm -f "$RUNTIME_CONFIG"
    : > "$RESEED_MARKER" 2>/dev/null || true
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

# TLS material.
#
# A certificate and its key are one thing, not two files, and every rule below
# follows from that. Staging them independently produced a runtime directory
# holding the host's certificate next to a key generated in the container: both
# files present, both readable, and no possible handshake. It only appeared to
# work because the server had already loaded the pair before the second service
# started and overwrote half of it.
#
# So: take both from the host or neither, and check that what ends up in place
# actually matches before trusting it.
#
# Staged rather than read in place because a private key has to be 0600 and
# owned by the user that reads it, while a bind mount carries the host's
# ownership — and this process is not the host user.

pair_matches() {
    _crt="$1"; _key="$2"
    [ -s "$_crt" ] && [ -s "$_key" ] || return 1
    command -v openssl >/dev/null 2>&1 || return 0  # cannot check; assume caller knows
    _c=$(openssl x509 -noout -modulus -in "$_crt" 2>/dev/null) || return 1
    _k=$(openssl rsa -noout -modulus -in "$_key" 2>/dev/null) || return 1
    [ "$_c" = "$_k" ]
}

if [ -r /app/config/test.crt ] && [ -r /app/config/test.key ]; then
    # Both halves are readable: the host's pair wins, so a renewed certificate
    # takes effect on the next start.
    cp /app/config/test.crt "$RUNTIME_DIR/test.crt" 2>/dev/null || true
    cp /app/config/test.key "$RUNTIME_DIR/test.key" 2>/dev/null || true
    chmod 600 "$RUNTIME_DIR/test.key" 2>/dev/null || true
    chmod 644 "$RUNTIME_DIR/test.crt" 2>/dev/null || true
fi

# The mail-auth development lab mounts a generated RSA fixture read-only. Stage
# it like TLS keys so the runtime process owns a 0600 copy; production images do
# nothing unless the explicitly named development fixture is mounted.
if [ -r /app/config/mailauth.key ]; then
    cp /app/config/mailauth.key "$RUNTIME_DIR/mailauth.key" 2>/dev/null || true
    chmod 600 "$RUNTIME_DIR/mailauth.key" 2>/dev/null || true
fi

# A development stack generates its own pair when it does not have a usable one.
#
# The usual reason is that the host's key is 0600 and owned by whoever ran
# `make certs`, so it is unreadable here whatever the bind mount says.
# Generating inside the container sidesteps ownership entirely: the file is
# created by the user that will read it.
#
# Gated on ELEMTA_DEV_CERT, deliberately. A server that quietly issues itself a
# certificate when its real one is missing looks healthy while being untrusted
# by every sender; in production the right behaviour is to fail loudly, which is
# what happens without this.
if ! pair_matches "$RUNTIME_DIR/test.crt" "$RUNTIME_DIR/test.key"; then
    if [ "${ELEMTA_DEV_CERT:-}" = "true" ] && command -v openssl >/dev/null 2>&1; then
        days="${ELEMTA_DEV_CERT_DAYS:-7}"
        host="${ELEMTA_HOSTNAME:-mail.dev.evil-admin.com}"
        echo "prepare-config: generating a ${days}-day self-signed development certificate" >&2
        if openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$RUNTIME_DIR/test.key.new" \
            -out "$RUNTIME_DIR/test.crt.new" \
            -days "$days" \
            -subj "/CN=${host}/O=Elemta Dev/C=US" \
            -addext "subjectAltName=DNS:${host},DNS:localhost" >/dev/null 2>&1; then
            # Move into place only once both halves exist, so a failure part-way
            # through cannot leave the mismatch this whole block exists to avoid.
            chmod 600 "$RUNTIME_DIR/test.key.new" 2>/dev/null || true
            chmod 644 "$RUNTIME_DIR/test.crt.new" 2>/dev/null || true
            mv "$RUNTIME_DIR/test.key.new" "$RUNTIME_DIR/test.key"
            mv "$RUNTIME_DIR/test.crt.new" "$RUNTIME_DIR/test.crt"
        else
            rm -f "$RUNTIME_DIR/test.crt.new" "$RUNTIME_DIR/test.key.new"
            echo "prepare-config: certificate generation failed" >&2
        fi
    elif [ -e "$RUNTIME_DIR/test.crt" ] || [ -e "$RUNTIME_DIR/test.key" ]; then
        echo "prepare-config: the TLS certificate and key do not match; TLS will fail to start" >&2
    fi
fi

# The dashboard's user file.
#
# Authentication is on by default, and the server refuses to start without this
# file — correctly, since the alternative is an admin interface that anyone can
# reach. But it cannot be created before the service exists either, so an empty
# one is placed here: the service starts, and nobody can log in until an account
# is added with `elemta user add` (which `make install-dev` does).
#
# Empty means locked, not open. That is the safe direction, and it beats a crash
# loop that takes the health probes down with it when the fix is one command.
if [ ! -e "$RUNTIME_DIR/users.json" ]; then
    printf '{}' > "$RUNTIME_DIR/users.json" 2>/dev/null || true
    chmod 600 "$RUNTIME_DIR/users.json" 2>/dev/null || true
fi

echo "$RUNTIME_CONFIG"
