#!/bin/sh
# Backs up the whole Compose stack while it runs:
#
#   mailbox/   Postgres metadata and message bodies (scripts/mailbox-backup.sh)
#   ldap/      the directory: accounts, aliases, passwords (slapcat), and
#              its configuration for reference (restores create a fresh one)
#   mta/       the MTA's queue (mail accepted but not yet delivered) and the
#              runtime configuration the dashboard saves, with its users file
#   secrets.tar.gz  deployments/compose/.secrets: TLS and DKIM keys, service
#              passwords, the TOTP encryption key. Without it the mailbox
#              can't decrypt anyone's two-step verification.
#
#   scripts/backup.sh <new directory>
#
# Set BACKUP_AGE_RECIPIENT to an age public key to encrypt the secrets
# archive (needs age on the host). Without it the archive is plaintext,
# readable only by its owner; keep the whole backup somewhere as safe as
# the server itself.
#
# Run scripts/restore-drill.sh on every new backup, or at least regularly:
# a backup nobody has restored is a guess.
#
# Settings: ELEMTA_VOLUME_PREFIX (default from .secrets/cloud.env, else
# elemta: the stack's volumes are <prefix>_<volume>), MAILBOX_IMAGE (an image with tar; default the
# running mailbox replica's).
set -eu
out=${1:?usage: $0 <directory>}
root=$(cd "$(dirname "$0")/.." && pwd)
secrets=$root/deployments/compose/.secrets
[ ! -e "$out" ] || { echo "Backup destination already exists: $out" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
volumes=$(volume_prefix "$secrets/cloud.env")
mailbox=$(svc_container mailbox-server)
image=${MAILBOX_IMAGE:-$(docker inspect -f '{{.Config.Image}}' "$mailbox")}
parent=$(dirname "$out")
mkdir -p "$parent"
stage=$(mktemp -d "$parent/.elemta-backup.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
chmod 700 "$stage"

echo "== Mailbox"
MAILBOX_IMAGE=$image MAILBOX_BODIES_VOLUME=${volumes}_mailbox_bodies "$root/scripts/mailbox-backup.sh" "$stage/mailbox" >/dev/null

echo "== Directory"
mkdir "$stage/ldap"
# Any node of a replicated directory holds all of it; its configuration is
# the first node's.
# shellcheck source=SCRIPTDIR/lib/ldap.sh
. "$root/scripts/lib/ldap.sh"
ldap=$(ldap_first)
docker exec "$ldap" slapcat -n 0 >"$stage/ldap/config.ldif"
docker exec "$ldap" slapcat -n 1 >"$stage/ldap/data.ldif"
grep -q '^dn: ' "$stage/ldap/data.ldif" || { echo "The directory export is empty" >&2; exit 1; }

echo "== MTA queue and runtime configuration"
mkdir "$stage/mta"
for v in elemta_queue elemta_config; do
    # As for bodies (mailbox-backup.sh): a live queue changes while it's
    # read; tar's exit 1 for that is fine, 2 is an error.
    docker run --rm --network none --entrypoint sh -v "${volumes}_$v:/v:ro" "$image" \
        -c 'tar --warning=no-file-changed -C /v -czf - .; [ $? -le 1 ]' >"$stage/mta/$v.tar.gz"
done

echo "== Secrets"
# In a container as root: the DKIM keys belong to the container user, so
# the host user deploying the stack can't read them itself.
docker run --rm --network none --user 0 --entrypoint tar -v "$secrets:/.secrets:ro" "$image" -C / -czf - .secrets >"$stage/secrets.tar.gz"
if [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
    age -r "$BACKUP_AGE_RECIPIENT" -o "$stage/secrets.tar.gz.age" "$stage/secrets.tar.gz"
    rm "$stage/secrets.tar.gz"
fi

{
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # From a mailbox replica: they run throughout, while the MTA may have
    # been stopped for a quiet backup.
    echo "version=$(docker exec "$mailbox" /app/elemta version 2>/dev/null | tail -1)"
    echo "ldap_entries=$(grep -c '^dn: ' "$stage/ldap/data.ldif")"
    (cd "$stage" && find . -type f ! -name manifest ! -name complete ! -path './mailbox/*' | sort | while read -r f; do
        echo "sha256 $(sha256sum "$f" | cut -d ' ' -f 1) $f"
    done)
} >"$stage/manifest"
: >"$stage/complete"
[ ! -e "$out" ] || { echo "Backup destination appeared during run: $out" >&2; exit 1; }
mv "$stage" "$out"
trap - EXIT HUP INT TERM
cat "$out/manifest" "$out/mailbox/manifest"
