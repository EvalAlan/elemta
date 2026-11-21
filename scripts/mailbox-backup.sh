#!/bin/sh
# Backs up the Compose stack's mailbox service: a consistent Postgres dump
# of the metadata, a base backup when WAL is archived, then the message
# bodies.
#
#   scripts/mailbox-backup.sh <directory>
#
# Order matters. Bodies are written before the metadata that refers to
# them and are never changed, so a dump taken first only refers to bodies
# that already exist, and copying the bodies afterwards picks them all up.
# Bodies removed by cleanup between the two steps are ones no message
# referred to for [maintenance] body_grace_hours, so they can't be in the
# dump. Because the backup holds its own copy, it stays restorable however
# long it is kept, even with a short grace period.
#
# Bodies come out through the running service, as they are stored, so this
# works the same for a volume and for a bucket and needs no bucket keys here.
# Every body is copied every time.
#
# BACKUP_BODIES=external leaves the bodies out, for a store that keeps its
# own history: a bucket with versioning, whose old versions are kept at
# least as long as the backups. The backup is then the metadata alone, a
# small fraction of the mail, and restoring it points back at the bodies
# where they are. Without that history a body deleted after the backup
# (body_grace_hours after its message) is gone, and so is that message.
#
# Settings: MAILBOX_CONTAINER (default the first mailbox replica),
# BACKUP_BODIES (copy, the default, or external).
set -eu
out=${1:?usage: $0 <directory>}
db=${MAILBOX_DB_CONTAINER:-elemta-mailbox-db}
dbuser=${MAILBOX_DB_USER:-}
dbname=${MAILBOX_DB_NAME:-}
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$(dirname "$0")/lib/compose.sh"
mailbox=${MAILBOX_CONTAINER:-$(svc_container mailbox-server)}
bodies=${BACKUP_BODIES:-copy}
case $bodies in
copy | external) ;;
*) echo "BACKUP_BODIES must be copy or external, not $bodies" >&2; exit 1 ;;
esac
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

# With continuous archiving on (docker-compose.yml, scripts/wal-offsite.sh),
# a base backup too: the database's files as they are, which a restore can
# roll forward with the archived WAL to any later moment (restore.sh --wal).
# -X fetch puts the WAL the copy needs in the tar, so it starts consistent
# on its own, and the drill can start it without the archive.
base=false
if docker exec "$db" test -f /wal-archive/.enabled 2>/dev/null; then
    echo "Base backup from $db"
    docker exec -e ELEMTA_BACKUP_DB_USER="$dbuser" "$db" sh -c '
        user=${ELEMTA_BACKUP_DB_USER:-${POSTGRES_USER:-postgres}}
        pg_basebackup -U "$user" -D - -Ft -X fetch --checkpoint=fast | gzip
    ' >"$stage/base.tar.gz"
    # Read to the end: grep -q would stop early and tar complain of a write error.
    tar -tzf "$stage/base.tar.gz" | grep -x backup_label >/dev/null || { echo "The base backup has no backup_label" >&2; exit 1; }
    base=true
fi

if [ "$bodies" = copy ]; then
    echo "Copying bodies from $mailbox"
    docker exec "$mailbox" /app/elemta mailbox export-bodies --config /etc/elemta/mailbox.toml >"$stage/bodies.tar.gz"
    tar -tzf "$stage/bodies.tar.gz" >/dev/null
else
    echo "Bodies stay in their store (BACKUP_BODIES=external)"
fi

docker run --rm -i --network none postgres:17-alpine pg_restore -l <"$stage/metadata.dump" >/dev/null
{
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "bodies=$bodies"
    echo "metadata_bytes=$(wc -c <"$stage/metadata.dump")"
    echo "metadata_sha256=$(sha256sum "$stage/metadata.dump" | cut -d ' ' -f 1)"
    if $base; then
        echo "base_bytes=$(wc -c <"$stage/base.tar.gz")"
        echo "base_sha256=$(sha256sum "$stage/base.tar.gz" | cut -d ' ' -f 1)"
        echo "base_wal_start=$(tar -xzOf "$stage/base.tar.gz" backup_label | sed -n 's/^START WAL LOCATION: .* (file \([0-9A-F]*\))$/\1/p')"
    fi
    if [ "$bodies" = copy ]; then
        echo "bodies_bytes=$(wc -c <"$stage/bodies.tar.gz")"
        echo "bodies_sha256=$(sha256sum "$stage/bodies.tar.gz" | cut -d ' ' -f 1)"
    fi
} >"$stage/manifest"
: >"$stage/complete"
[ ! -e "$out" ] || { echo "Backup destination appeared during run: $out" >&2; exit 1; }
mv "$stage" "$out"
trap - EXIT HUP INT TERM
cat "$out/manifest"
