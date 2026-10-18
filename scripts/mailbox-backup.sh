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
bodies=${MAILBOX_BODIES_VOLUME:-compose_mailbox_bodies}
image=${MAILBOX_IMAGE:-elemta-mailbox:dev}
mkdir -p "$out"
chmod 700 "$out"

echo "Dumping metadata from $db"
docker exec "$db" sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' >"$out/metadata.dump"

echo "Copying bodies from volume $bodies"
docker run --rm --network none --entrypoint tar -v "$bodies:/bodies:ro" "$image" -C /bodies -czf - . >"$out/bodies.tar.gz"

messages=$(docker exec "$db" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select count(*) from mailbox_messages"')
{
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "messages=$messages"
    echo "metadata_bytes=$(wc -c <"$out/metadata.dump")"
    echo "bodies_bytes=$(wc -c <"$out/bodies.tar.gz")"
} >"$out/manifest"
cat "$out/manifest"
