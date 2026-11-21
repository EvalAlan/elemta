#!/bin/sh
# Takes the mailbox database's archived WAL files off the server. Run every
# 5 minutes by the elemta-wal timer, which scripts/cloud-deploy.sh installs
# beside the elemta-backup timer when off-site backups are set up.
#
#   scripts/wal-offsite.sh
#
# Postgres copies each finished WAL file into the mailbox_wal volume
# (docker-compose.yml, archive_command). This seals each one to the age
# public key and uploads it to the backup bucket (elemta backup wal-push),
# removing the local copy once the object is confirmed. With the six-hourly
# backups' base backups, that lets a restore reach any moment
# (scripts/restore.sh --wal), not just the last backup.
#
# Uploads that fail leave the files where they are, oldest first, for the
# next run; backup-offsite.sh reports a backlog on the Health page.
#
# Settings: the same file as backup-offsite.sh (BACKUP_ENV_FILE, default
# /etc/elemta/secrets/backup-storage.env), handed to the container as its
# environment and never read into this shell. BACKUP_IMAGE as there.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
env_file=${BACKUP_ENV_FILE:-/etc/elemta/secrets/backup-storage.env}
[ -f "$env_file" ] || { echo "wal-offsite: no $env_file, so off-site backups aren't set up" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
volumes=$(volume_prefix "$root/deployments/compose/.secrets/cloud.env")
# From any mailbox-server container, running or not: a restore stops them
# and then asks for this to be run.
image=${BACKUP_IMAGE:-$(docker ps -a --filter label=com.docker.compose.service=mailbox-server --format '{{.Image}}' | head -n 1)}
[ -n "$image" ] || { echo "wal-offsite: no mailbox-server container to take the image from; set BACKUP_IMAGE" >&2; exit 1; }
docker run --rm --user 0 --env-file "$env_file" -v "${volumes}_mailbox_wal:/wal" "$image" backup wal-push /wal
