#!/bin/sh
# Backs up the whole Compose stack while it runs:
#
#   mailbox/   Postgres metadata and message bodies (scripts/mailbox-backup.sh);
#              BACKUP_BODIES=external leaves the bodies in a versioned bucket
#   objects/   webmail's calendars, contacts, tasks and settings, when they are
#              in their own database (docs/webmail-object-storage.md). By
#              default they are messages in the mailbox and need nothing here.
#   ldap/      the directory: accounts, aliases, passwords (slapcat), and
#              its configuration for reference (restores create a fresh one)
#   mta/       the MTA's queue (mail accepted but not yet delivered) and the
#              runtime configuration the dashboard saves, with its users file
#   rspamd/    what the spam filter has learned (its Valkey, with the Bayes
#              tokens trained from Junk moves) and its own data directory.
#              Weeks of training, which a fresh install starts without
#   secrets.tar.gz  deployments/compose/.secrets: TLS and DKIM keys, service
#              passwords, the TOTP encryption key, the message body key.
#              Without it the mailbox can't decrypt anyone's two-step
#              verification, or an encrypted body. The re-downloadable
#              location database (.secrets/geoip) is left out.
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
MAILBOX_CONTAINER=$mailbox "$root/scripts/mailbox-backup.sh" "$stage/mailbox" >/dev/null

objects=$(svc_containers webmail-objects | head -n 1)
if [ -n "$objects" ]; then
    echo "== Webmail objects"
    mkdir "$stage/objects"
    docker exec "$objects" sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' >"$stage/objects/webmail-objects.dump"
fi

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

rspamd_valkey=$(svc_container rspamd-valkey)
if docker inspect "$rspamd_valkey" >/dev/null 2>&1; then
    echo "== Spam filter"
    mkdir "$stage/rspamd"
    # SAVE, not BGSAVE: it returns once the snapshot is on disk, so the copy
    # below holds what Rspamd has learned up to now.
    docker exec "$rspamd_valkey" valkey-cli SAVE >/dev/null
    for v in rspamd_valkey_data rspamd_data; do
        # As root: the files belong to the Rspamd and Valkey users.
        docker run --rm --network none --user 0 --entrypoint sh -v "${volumes}_$v:/v:ro" "$image" \
            -c 'tar --warning=no-file-changed --exclude="*.sock" -C /v -czf - .; [ $? -le 1 ]' >"$stage/rspamd/$v.tar.gz"
    done
fi

echo "== Secrets"
# In a container as root: the DKIM keys belong to the container user, so
# the host user deploying the stack can't read them itself.
# Not the location database for sign-in alerts: over 100 MB, and the deploy
# downloads it again (scripts/cloud-deploy.sh).
docker run --rm --network none --user 0 --entrypoint tar -v "$secrets:/.secrets:ro" "$image" -C / --exclude=.secrets/geoip -czf - .secrets >"$stage/secrets.tar.gz"
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
