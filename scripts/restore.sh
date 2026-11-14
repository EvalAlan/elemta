#!/usr/bin/env bash
# Restores a backup from scripts/backup.sh into this host's stack, replacing
# its mail, directory, queue and runtime configuration. Destructive: run
# scripts/restore-drill.sh on the backup first.
#
#   scripts/restore.sh <backup directory> --confirm [--wal <directory> [--to <time>]]
#
# With --wal, the mailbox database is rolled forward past the backup: its
# base backup is put in place and replayed with the WAL in <directory>
# (fetched and decrypted with elemta backup wal-get), to the end of that WAL,
# or with --to to a moment such as "2026-11-14 09:42:00+00" (just before a
# mistake). Everything else comes from the backup as it was taken, so pick
# the newest backup before the target. See docs/production-compose.md,
# "Restoring to a point in time".
#
# On a new host, check out the commit the backup records (commit= in its
# manifest), then run this. It puts the secrets back first (they hold the
# passwords, the body encryption key and the bucket settings everything else
# needs) and, finding no stack yet, stops and says to run cloud-deploy.sh and
# then this again. On a host that has its own .secrets they are kept and the
# backup's are left alone, unless ELEMTA_RESTORE_SECRETS=true.
#
# Mail that arrives while it runs isn't lost: the MTA is stopped first, so
# sending servers queue it and retry.
#
# Settings: ELEMTA_COMPOSE_PROJECT (default elemta), ELEMTA_VOLUME_PREFIX (default from .secrets/cloud.env, else elemta), ELEMTA_TAG (as for
# scripts/cloud-deploy.sh: set it to restore onto the release images).
set -euo pipefail
in=${1:?usage: $0 <backup directory> --confirm [--wal <directory> [--to <time>]]}
[ "${2:-}" = --confirm ] || { echo "restore: this replaces the stack's data; add --confirm" >&2; exit 1; }
shift 2
wal="" target=""
while [ $# -gt 0 ]; do
    case $1 in
    --wal) wal=$(cd "${2:?--wal needs a directory}" && pwd); shift 2 ;;
    --to) target=${2:?--to needs a time}; shift 2 ;;
    *) echo "restore: unknown option $1" >&2; exit 1 ;;
    esac
done
[ -z "$target" ] || [ -n "$wal" ] || { echo "restore: --to needs --wal" >&2; exit 1; }
# The target ends up inside postgresql.auto.conf between quotes.
case $target in *[\'\\]*) echo "restore: --to must not contain quotes or backslashes" >&2; exit 1 ;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
compose_dir=$root/deployments/compose
secrets=$compose_dir/.secrets
project=${ELEMTA_COMPOSE_PROJECT:-elemta}
in=$(cd "$in" && pwd)
[ -f "$in/complete" ] || { echo "restore: backup is incomplete" >&2; exit 1; }
[ -z "$wal" ] || [ -f "$in/mailbox/base.tar.gz" ] ||
    { echo "restore: this backup has no base backup (WAL archiving wasn't on), so it can't be rolled forward" >&2; exit 1; }
# Replay only goes forward from the backup: Postgres given an earlier target
# would quietly stop at the backup's own moment instead.
if [ -n "$target" ]; then
    created=$(sed -n 's/^created=//p' "$in/manifest")
    t=$(date -u -d "$target" +%s 2>/dev/null) || { echo "restore: --to $target isn't a time date(1) understands" >&2; exit 1; }
    [ "$t" -ge "$(date -u -d "$created" +%s)" ] ||
        { echo "restore: $target is before this backup was taken ($created); use an older backup" >&2; exit 1; }
fi
step() { printf '\n==> %s\n' "$*"; }

step "Checksums"
grep '^sha256 ' "$in/manifest" | while read -r _ sum file; do
    [ "$(sha256sum "$in/$file" | cut -d ' ' -f 1)" = "$sum" ] || { echo "restore: checksum differs: $file" >&2; exit 1; }
done

restored_secrets=false
if [ ! -d "$secrets" ] || [ "${ELEMTA_RESTORE_SECRETS:-}" = true ]; then
    step "Secrets"
    [ -f "$in/secrets.tar.gz" ] || { echo "restore: decrypt secrets.tar.gz.age into the backup first (age -d)" >&2; exit 1; }
    docker run --rm --network none --user 0 --entrypoint tar -v "$compose_dir:/c" -i alpine:3.22 -C /c -xzf - <"$in/secrets.tar.gz"
    restored_secrets=true
fi

# A new host has no stack to restore into: the data goes into the stack's
# volumes and is restored with its images, which don't exist yet. The way
# through, proven in a restore rehearsal: the backup's secrets first (just
# done), then cloud-deploy.sh builds the images and starts an empty stack
# with them, then this again puts the data in. The empty stack is safe for
# mail kept in a bucket: the mailbox only ever deletes bodies its database
# records as unreferenced, and an empty database records none.
if [ -z "$(docker ps -aq --filter label=com.docker.compose.service=mailbox-server)" ]; then
    {
        echo
        echo "restore: this host has no stack yet, so there is nothing to restore into."
        if $restored_secrets; then
            echo "  The backup's secrets are in place now. Next:"
        else
            echo "  This host already had $secrets, so the backup's were NOT put back."
            echo "  On a new host you almost certainly want the backup's: they hold the key"
            echo "  that decrypts the message bodies and the bucket settings. Move that"
            echo "  directory aside, or set ELEMTA_RESTORE_SECRETS=true, and run this again."
            echo "  Then:"
        fi
        echo "    1. scripts/cloud-deploy.sh          builds the images and starts an empty stack"
        echo "    2. scripts/restore.sh $1 --confirm  again, to restore the data into it"
    } >&2
    exit 3
fi
env_file=$secrets/cloud.env
files=(-f "$compose_dir/docker-compose.yml" -f "$compose_dir/docker-compose.cloud.yml")
[ -z "${ELEMTA_TAG:-}" ] || files+=(-f "$compose_dir/docker-compose.release.yml")
dc() { docker compose -p "$project" --env-file "$env_file" "${files[@]}" "$@"; }

# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
volumes=$(volume_prefix "$secrets/cloud.env")

if [ -n "$wal" ]; then
    # WAL still waiting here isn't in what was fetched, and a history file
    # among it is how Postgres knows which timeline numbers are taken.
    # Checked before anything stops; on a new host it's empty.
    pending=$(docker run --rm --network none --user 0 --entrypoint sh -v "${volumes}_mailbox_wal:/w" postgres:17-alpine \
        -c 'find /w -maxdepth 1 -type f ! -name ".*" | wc -l')
    if [ "$pending" != 0 ]; then
        echo "restore: $pending WAL files on this host haven't been uploaded yet. Run scripts/wal-offsite.sh, fetch again with elemta backup wal-get, then restore." >&2
        exit 1
    fi
fi

step "Stopping mail services"
dc stop elemta elemta-admin elemta-webmail elemta-mailbox mailbox-server elemta-ldap
# The spam filter too, when its training is being put back: its Valkey
# would otherwise write its own snapshot over the restored one.
[ ! -d "$in/rspamd" ] || dc stop elemta-rspamd rspamd-valkey
dc up -d elemta-mailbox-db
until docker exec elemta-mailbox-db sh -c 'pg_isready -q -U "$POSTGRES_USER"'; do sleep 1; done
image=$(docker inspect -f '{{.Config.Image}}' "$(docker ps -a --filter label=com.docker.compose.service=mailbox-server --format '{{.Names}}' | sort | head -n 1)")
ldap_image=$(docker inspect -f '{{.Config.Image}}' elemta-ldap)
# load <volume> <archive> [owner]: replace a volume's contents.
load() {
    docker run --rm -i --network none --user 0 --entrypoint sh -v "${volumes}_$1:/v" "$image" \
        -c "find /v -mindepth 1 -delete && tar -C /v -xzf - ${3:+&& chown -R $3 /v}" <"$2"
}

if [ -z "$wal" ]; then
    step "Mailbox metadata"
    docker exec -i elemta-mailbox-db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --exit-on-error' <"$in/mailbox/metadata.dump"
else
    step "Mailbox metadata, rolled forward${target:+ to $target}"
    # The base backup replaces the database's files and the stack's own
    # Postgres replays the WAL into them, stopping at the target (or the
    # end) and carrying on as a new timeline. It archives as it goes, so the
    # new timeline's history file reaches the bucket with the WAL after it:
    # a later restore needs it to follow this one, and to pick a timeline
    # of its own. The fetched WAL waits in the archive volume's restore/
    # directory, which the uploader leaves alone, and goes once it's used.
    [ "$(sha256sum "$in/mailbox/base.tar.gz" | cut -d ' ' -f 1)" = "$(sed -n 's/^base_sha256=//p' "$in/mailbox/manifest")" ] ||
        { echo "restore: base backup checksum differs" >&2; exit 1; }
    dc stop elemta-mailbox-db
    docker run --rm -i --network none --user 0 --entrypoint sh -v "${volumes}_mailbox_metadata:/d" postgres:17-alpine -c '
        find /d -mindepth 1 -delete && tar -xzf - -C /d && touch /d/recovery.signal &&
        chown -R 70:70 /d && chmod 700 /d' <"$in/mailbox/base.tar.gz"
    {
        echo "restore_command = 'cp /wal-archive/restore/%f %p'"
        echo "recovery_target_action = 'promote'"
        [ -z "$target" ] || echo "recovery_target_time = '$target'"
    } | docker run --rm -i --network none --user 0 --entrypoint sh -v "${volumes}_mailbox_metadata:/d" postgres:17-alpine \
        -c 'cat >>/d/postgresql.auto.conf'
    # Fetched WAL belongs to whoever ran wal-get; Postgres reads it as its
    # own user.
    docker run --rm --network none --user 0 --entrypoint sh -v "$wal:/src:ro" -v "${volumes}_mailbox_wal:/w" postgres:17-alpine \
        -c 'rm -rf /w/restore && mkdir -p /w/restore && cp /src/* /w/restore/ && chown -R 70:70 /w && chmod 700 /w /w/restore'
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    dc up -d elemta-mailbox-db
    # A recovery that fails (a target before the backup, a missing WAL
    # file) stops Postgres, and the restart policy starts it again: either
    # ends the wait.
    restarts=$(docker inspect -f '{{.RestartCount}}' elemta-mailbox-db)
    done_recovery=false
    for _ in $(seq 600); do
        [ "$(docker inspect -f '{{.State.Running}}' elemta-mailbox-db 2>/dev/null)" = true ] || break
        [ "$(docker inspect -f '{{.RestartCount}}' elemta-mailbox-db)" = "$restarts" ] || break
        if [ "$(docker exec elemta-mailbox-db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select not pg_is_in_recovery()"' 2>/dev/null)" = t ]; then
            done_recovery=true
            break
        fi
        sleep 2
    done
    docker logs --since "$since" elemta-mailbox-db 2>&1 | grep -E 'recovery stopping|redo done|last completed transaction|selected new timeline|FATAL|PANIC' |
        grep -v -e 'is starting up' -e 'not yet accepting connections' || true
    $done_recovery || {
        dc stop elemta-mailbox-db
        echo "restore: the database didn't finish recovering; see the log above. It is stopped, holding the base backup." >&2
        exit 1
    }
    # The recovery settings would only confuse a later restore of this
    # cluster.
    docker exec elemta-mailbox-db sh -c 'psql -q -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "ALTER SYSTEM RESET restore_command" \
        -c "ALTER SYSTEM RESET recovery_target_action" -c "ALTER SYSTEM RESET recovery_target_time" -c "SELECT pg_reload_conf()"' >/dev/null
    docker run --rm --network none --user 0 --entrypoint sh -v "${volumes}_mailbox_wal:/w" postgres:17-alpine -c 'rm -rf /w/restore'
fi
if [ "$(sed -n 's/^bodies=//p' "$in/mailbox/manifest")" = external ]; then
    # The metadata names the bucket the bodies are in; the deploy puts its
    # keys back (they aren't in the backup).
    step "Message bodies stay in their store (backed up with BACKUP_BODIES=external)"
else
    step "Message bodies"
    load mailbox_bodies "$in/mailbox/bodies.tar.gz" 1001:1001
fi
if [ -f "$in/objects/webmail-objects.dump" ]; then
    step "Webmail objects"
    objects=$(docker ps --filter label=com.docker.compose.service=webmail-objects --format '{{.Names}}' | head -n 1)
    [ -n "$objects" ] || { echo "restore: the backup has webmail objects but webmail-objects isn't running; start it (docs/webmail-object-storage.md) and run this again" >&2; exit 1; }
    docker exec -i "$objects" sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --exit-on-error' <"$in/objects/webmail-objects.dump"
fi

step "Directory"
# Created afresh from the entries, as on a new install: the configuration
# comes from the image and the access rules and passwords from the deploy
# scripts once it runs, so a backup taken under the previous directory image
# restores the same way as a current one.
docker run --rm --network none --user 0 --entrypoint sh --env-file "$secrets/ldap-admin.env" \
    -v "${volumes}_ldap_slapd:/etc/ldap/slapd.d" -v "${volumes}_ldap_db:/var/lib/ldap" \
    -v "$in/ldap/data.ldif:/import/data.ldif:ro" "$ldap_image" \
    -c 'find /etc/ldap/slapd.d /var/lib/ldap -mindepth 1 -delete && elemta-ldap init'

step "MTA queue and runtime configuration"
load elemta_queue "$in/mta/elemta_queue.tar.gz" 1001:1001
load elemta_config "$in/mta/elemta_config.tar.gz" 1001:1001

if [ -d "$in/rspamd" ]; then
    step "Spam filter"
    # Extracted as root, so the files keep the Rspamd and Valkey owners
    # they were saved with.
    load rspamd_valkey_data "$in/rspamd/rspamd_valkey_data.tar.gz"
    load rspamd_data "$in/rspamd/rspamd_data.tar.gz"
fi

step "Starting the stack"
# The restored runtime configuration is kept, not reseeded from the host.
ELEMTA_CONFIG_RESEED=false dc up -d
# By service: a scaled service has several containers, with Compose's names.
for svc in elemta-ldap mailbox-server elemta elemta-webmail elemta-admin; do
    for c in $(svc_containers "$svc"); do
        for _ in $(seq 100); do
            [ "$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)" = healthy ] && break
            sleep 3
        done
        echo "$c $(docker inspect -f '{{.State.Health.Status}}' "$c")"
    done
    if [ "$svc" = elemta-ldap ]; then
        "$root/scripts/ldap-schema.sh"
        "$root/scripts/ldap-admin-password.sh"
        "$root/scripts/ldap-service-accounts.sh"
    fi
done
echo "Restored $(sed -n 's/^created=//p' "$in/manifest") ($(sed -n 's/^version=//p' "$in/manifest"))"
