#!/bin/sh
# Backs up the stack and keeps the backup off the server. Run daily by the
# elemta-backup timer, which scripts/cloud-deploy.sh installs when the
# settings file below exists; run it by hand the same way.
#
#   scripts/backup-offsite.sh
#
# Each run:
#   1. scripts/backup.sh with BACKUP_BODIES=external: the message bodies stay
#      in their bucket, whose versioning keeps what's deleted, so the backup
#      is the metadata, directory, queue, configuration, spam filter and
#      secrets: a few megabytes.
#   2. Once a week (BACKUP_DRILL_DAYS), scripts/restore-drill.sh on that
#      backup before it's sealed. The drill needs the backup unencrypted,
#      and this is the only place it is, so the private key never has to
#      come near the server for it.
#   3. elemta backup upload: encrypts it to the age public key and uploads it
#      as it's encrypted. No sealed copy is written here, and nothing beyond
#      the mailbox image is needed on the host.
#   4. elemta backup prune: keeps the newest backup of each of the last 14
#      days and 8 weeks (BACKUP_KEEP_DAILY, BACKUP_KEEP_WEEKLY). The bucket's
#      versioning keeps what's pruned a while longer.
#   5. Deletes the local, unencrypted backup.
#
# The result goes to backup-status.json in the runtime configuration volume,
# where the admin console's Health page reads it, and to the journal
# (journalctl -u elemta-backup).
#
# Settings file (root-only): BACKUP_ENV_FILE, default
# /etc/elemta/secrets/backup-storage.env, with BACKUP_S3_ENDPOINT,
# BACKUP_S3_REGION, BACKUP_S3_BUCKET, BACKUP_S3_ACCESS_KEY_ID,
# BACKUP_S3_SECRET_ACCESS_KEY and BACKUP_AGE_RECIPIENT. It is handed to the
# upload container as its environment and never read into this shell.
# Also: BACKUP_WORK_DIR (default /var/lib/elemta-backup), BACKUP_IMAGE.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
env_file=${BACKUP_ENV_FILE:-/etc/elemta/secrets/backup-storage.env}
work=${BACKUP_WORK_DIR:-/var/lib/elemta-backup}
drill_days=${BACKUP_DRILL_DAYS:-7}
[ -f "$env_file" ] || { echo "backup-offsite: no $env_file, so off-site backups aren't set up" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
volumes=$(volume_prefix "$root/deployments/compose/.secrets/cloud.env")
# The mailbox image carries the elemta binary; BACKUP_IMAGE picks another.
image=${BACKUP_IMAGE:-$(docker inspect -f '{{.Config.Image}}' "$(svc_container mailbox-server)")}
mkdir -p "$work"
chmod 700 "$work"
name=elemta-$(date -u +%Y%m%dT%H%M%SZ)
dir=$work/$name
stage=backup object="" bytes=0 drilled=false

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
remembered() { cat "$work/$1" 2>/dev/null || true; }
days_since() {
    [ -n "$1" ] || { echo 9999; return; }
    echo $((($(date -u +%s) - $(date -u -d "$1" +%s)) / 86400))
}

# status <ok> <message>: what the Health page shows. The message is one of
# the fixed sentences below, never a command's output, so it needs no
# escaping and can't carry a secret.
status() {
    printf '{"attempted":"%s","ok":%s,"stage":"%s","message":"%s","object":"%s","bytes":%s,"last_success":"%s","last_drill":"%s","drill_ok":%s}\n' \
        "$(now)" "$1" "$stage" "$2" "$object" "$bytes" "$(remembered last-success)" "$(remembered last-drill)" \
        "$([ "$(remembered last-drill-failed)" = yes ] && echo false || echo true)" |
        docker run --rm -i --network none --user 0 --entrypoint sh -v "${volumes}_elemta_config:/c" "$image" \
            -c 'cat >/c/backup-status.json.new && chmod 644 /c/backup-status.json.new && mv /c/backup-status.json.new /c/backup-status.json' ||
        echo "backup-offsite: couldn't write the status file" >&2
}

finish() {
    code=$?
    rm -rf "$dir"
    if [ "$code" -ne 0 ]; then
        echo "backup-offsite: failed during the $stage step" >&2
        status false "The backup failed during the $stage step. See journalctl -u elemta-backup on the server."
    fi
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

echo "== Backup ($name)"
BACKUP_BODIES=external "$root/scripts/backup.sh" "$dir"

if [ "$(days_since "$(remembered last-drill)")" -ge "$drill_days" ]; then
    stage=drill
    echo "== Restore drill"
    if "$root/scripts/restore-drill.sh" "$dir"; then
        rm -f "$work/last-drill-failed"
    else
        # Recorded, and the backup still goes off-site: a backup that failed
        # its drill is worth keeping until someone has looked at why.
        echo yes >"$work/last-drill-failed"
    fi
    now >"$work/last-drill"
    drilled=true
fi

stage=upload
echo "== Upload"
out=$(docker run --rm --user 0 --env-file "$env_file" -v "$dir:/backup/$name:ro" "$image" backup upload "/backup/$name")
echo "$out"
object=$(echo "$out" | sed -n 's/^uploaded \([^ ]*\) .*/\1/p' | tail -n 1)
bytes=$(echo "$out" | sed -n 's/^uploaded [^ ]* (\([0-9]*\) bytes)$/\1/p' | tail -n 1)
[ -n "$object" ] && [ -n "$bytes" ] || { echo "backup-offsite: the upload didn't report what it stored" >&2; exit 1; }

stage=prune
echo "== Prune"
docker run --rm --user 0 --env-file "$env_file" "$image" backup prune \
    --daily "${BACKUP_KEEP_DAILY:-14}" --weekly "${BACKUP_KEEP_WEEKLY:-8}"

now >"$work/last-success"
stage="done"
if [ "$(remembered last-drill-failed)" = yes ]; then
    status true "Backed up, but the last restore drill failed. Run scripts/restore-drill.sh on a fresh backup to see why."
elif $drilled; then
    status true "Backed up and checked with a restore drill."
else
    status true "Backed up."
fi
echo "backup-offsite: $object, $bytes bytes"
