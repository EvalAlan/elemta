#!/bin/sh
# Backs up the Compose stack's mailbox service: a consistent Postgres dump
# of the metadata, then the message bodies.
#
#   scripts/mailbox-backup.sh <directory>
#
# Order matters. Bodies are written before the metadata that refers to
# them and are never changed, so a dump taken first only refers to bodies
# that already exist, and copying the bodies afterwards picks them all up.
# Bodies removed by cleanup between the two steps are ones no message
# referred to for [maintenance] body_grace_hours, so they can't be in the
# dump. Keep body_grace_hours above how long you keep backups.
set -eu
out=${1:?usage: $0 <directory>}
db=${MAILBOX_DB_CONTAINER:-elemta-mailbox-db}
dbuser=${MAILBOX_DB_USER:-}
dbname=${MAILBOX_DB_NAME:-}
bodies=${MAILBOX_BODIES_VOLUME:-elemta_mailbox_bodies}
image=${MAILBOX_IMAGE:-elemta-mailbox:dev}
[ ! -e "$out" ] || { echo "Backup destination already exists: $out" >&2; exit 1; }
parent=$(dirname "$out")
mkdir -p "$parent"
stage=$(mktemp -d "$parent/.mailbox-backup.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
chmod 700 "$stage"

echo "Dumping metadata from $db"
docker exec -e ELEMTA_BACKUP_DB_USER="$dbuser" -e ELEMTA_BACKUP_DB_NAME="$dbname" "$db" sh -c '
    user=${ELEMTA_BACKUP_DB_USER:-${POSTGRES_USER:-postgres}}
    database=${ELEMTA_BACKUP_DB_NAME:-${POSTGRES_DB:-$user}}
    pg_dump -U "$user" -d "$database" -Fc
' >"$stage/metadata.dump"

echo "Copying bodies from volume $bodies"
# Mail keeps arriving, so tar may see the directory change and exit 1 with
# a warning. That's expected: a body written after the dump isn't in it.
# Real errors exit 2.
docker run --rm --network none --entrypoint sh -v "$bodies:/bodies:ro" "$image" \
    -c 'tar --warning=no-file-changed -C /bodies -czf - .; [ $? -le 1 ]' >"$stage/bodies.tar.gz"

docker run --rm -i --network none postgres:17-alpine pg_restore -l <"$stage/metadata.dump" >/dev/null
tar -tzf "$stage/bodies.tar.gz" >/dev/null
{
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "metadata_bytes=$(wc -c <"$stage/metadata.dump")"
    echo "bodies_bytes=$(wc -c <"$stage/bodies.tar.gz")"
    echo "metadata_sha256=$(sha256sum "$stage/metadata.dump" | cut -d ' ' -f 1)"
    echo "bodies_sha256=$(sha256sum "$stage/bodies.tar.gz" | cut -d ' ' -f 1)"
} >"$stage/manifest"
: >"$stage/complete"
[ ! -e "$out" ] || { echo "Backup destination appeared during run: $out" >&2; exit 1; }
mv "$stage" "$out"
trap - EXIT HUP INT TERM
cat "$out/manifest"
