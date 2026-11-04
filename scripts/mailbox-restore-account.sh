#!/usr/bin/env bash
# Puts one account's lost mail, and with --data its calendars, contacts and
# the rest, back from a backup while the stack keeps running. Nothing the
# account has now is changed or overwritten, and it can be run again safely.
# Mail that is gone comes back under a "Restored <backup date>" folder.
#
#   scripts/mailbox-restore-account.sh <backup directory> <address> [options]
#
#     --dry-run        read everything and report, writing nothing
#     --folder NAME    only this folder of the backup (repeatable); needed for
#                      Junk and quarantine, which are otherwise left out
#     --all            also restore messages the account still has
#     --data           also restore what is missing of calendars, contacts,
#                      tasks, settings, filters and sender rules. These go
#                      straight back into use, so anything deleted on purpose
#                      since the backup returns too. Dry-run it first.
#
# --folder Calendar, Contacts, Tasks or Settings restores just that one.
# <backup directory> is one from scripts/backup.sh or scripts/mailbox-backup.sh.
# The account must exist.
#
# Settings: ELEMTA_COMPOSE_PROJECT (default elemta), ELEMTA_TAG (as for
# scripts/cloud-deploy.sh).
set -euo pipefail
in=${1:?usage: $0 <backup directory> <address> [--dry-run] [--all] [--folder NAME]...}
address=${2:?usage: $0 <backup directory> <address> [--dry-run] [--all] [--folder NAME]...}
shift 2
options=()
dry_run=false
data=false
collections=()
while [ $# -gt 0 ]; do
    case $1 in
    --all) options+=("$1") ;;
    --dry-run)
        dry_run=true
        options+=("$1")
        ;;
    --data)
        data=true
        options+=("$1")
        ;;
    --folder)
        [ $# -ge 2 ] || { echo "restore: --folder needs a name" >&2; exit 2; }
        options+=("--folder=$2")
        case $2 in Calendar | Contacts | Tasks | Settings) collections+=("$2") ;; esac
        shift
        ;;
    *)
        echo "restore: unknown option $1" >&2
        exit 2
        ;;
    esac
    shift
done

root=$(cd "$(dirname "$0")/.." && pwd)
compose_dir=$root/deployments/compose
secrets=$compose_dir/.secrets
project=${ELEMTA_COMPOSE_PROJECT:-elemta}
in=$(cd "$in" && pwd)
[ ! -f "$in/mailbox/manifest" ] || in=$in/mailbox
[ -f "$in/complete" ] && [ -f "$in/manifest" ] || { echo "restore: backup is incomplete" >&2; exit 1; }
for part in metadata:metadata.dump bodies:bodies.tar.gz; do
    want=$(sed -n "s/^${part%%:*}_sha256=//p" "$in/manifest")
    [ "$(sha256sum "$in/${part#*:}" | cut -d ' ' -f 1)" = "$want" ] || { echo "restore: checksum differs: ${part#*:}" >&2; exit 1; }
done
label=$(sed -n 's/^created=//p' "$in/manifest" | cut -c1-10)
[ -n "$label" ] || { echo "restore: the manifest has no date" >&2; exit 1; }

files=(-f "$compose_dir/docker-compose.yml")
env_args=()
if [ -f "$secrets/cloud.env" ]; then
    files+=(-f "$compose_dir/docker-compose.cloud.yml")
    env_args=(--env-file "$secrets/cloud.env")
fi
[ -z "${ELEMTA_TAG:-}" ] || files+=(-f "$compose_dir/docker-compose.release.yml")
dc() { docker compose -p "$project" "${env_args[@]}" "${files[@]}" "$@"; }

# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
db=${MAILBOX_DB_CONTAINER:-elemta-mailbox-db}
image=$(docker inspect -f '{{.Config.Image}}' "$(svc_container mailbox-server)")
run=$$
source_db=elemta_restore_$run
vol=elemta-restore-$run-bodies

# When webmail's objects have their own database, the mailbox's hidden folders
# only hold what was there before that move, and the backup's copy is a dump.
objects=$(svc_containers webmail-objects | head -n 1)
objects_dump=$in/../objects/webmail-objects.dump
if [ -n "$objects" ]; then
    options+=(--objects-elsewhere)
    if [ "$data" = true ]; then
        collections=(Calendar Contacts Tasks Settings)
    fi
    if [ ${#collections[@]} -gt 0 ] && [ ! -f "$objects_dump" ]; then
        echo "restore: this backup has no webmail objects database; it needs one from scripts/backup.sh" >&2
        exit 1
    fi
fi

cleanup() {
    [ -z "$objects" ] || docker exec "$objects" sh -c 'dropdb -U "$POSTGRES_USER" --force --if-exists "$1"' sh "$source_db" >/dev/null 2>&1 || true
    docker exec "$db" sh -c 'dropdb -U "$POSTGRES_USER" --force --if-exists "$1"' sh "$source_db" >/dev/null 2>&1 || true
    docker volume rm "$vol" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The backup's metadata goes in a database of its own on the mailbox's server,
# which the restore container can reach already and which needs no new network
# or password. Live data isn't touched: restoring only selects from this one.
echo "Loading the backup's metadata"
docker exec "$db" sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh "$source_db"
docker exec -i "$db" sh -c 'pg_restore -U "$POSTGRES_USER" -d "$1" --no-owner --exit-on-error' sh "$source_db" <"$in/metadata.dump"

echo "Unpacking the backup's bodies"
docker volume create "$vol" >/dev/null
docker run --rm -i --network none --user 0 --entrypoint sh -v "$vol:/bodies" "$image" \
    -c 'tar -C /bodies -xzf - && chown -R 1001:1001 /bodies' <"$in/bodies.tar.gz"

echo "Restoring $address from $label"
dc run --rm --no-deps -T -v "$vol:/restore/bodies:ro" mailbox-server mailbox restore-account \
    --config /etc/elemta/mailbox.toml --source-database "$source_db" --bodies /restore/bodies \
    --address "$address" --label "$label" --actor "${SUDO_USER:-${USER:-cli}}" "${options[@]}"

[ -n "$objects" ] && [ ${#collections[@]} -gt 0 ] || exit 0

# Across two databases on one server, COPY is the plain way: no extension to
# install. ON CONFLICT DO NOTHING keeps whatever the account has now, including
# an item a CalDAV client has renamed.
echo "Restoring webmail objects"
account_sql='SELECT id FROM mailbox_accounts WHERE lower(address)=lower(:'"'"'a'"'"') ORDER BY id LIMIT 1'
account_id=$(docker exec -i "$db" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -v a="$1"' sh "$address" <<<"$account_sql")
source_id=$(docker exec -i "$db" sh -c 'psql -U "$POSTGRES_USER" -d "$1" -tA -v a="$2"' sh "$source_db" "$address" <<<"$account_sql")
[ -n "$account_id" ] && [ -n "$source_id" ] || { echo "restore: no account $address" >&2; exit 1; }
wanted=$(IFS=,; echo "${collections[*]}")
end=COMMIT
[ "$dry_run" = false ] || end=ROLLBACK
docker exec "$objects" sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh "$source_db"
docker exec -i "$objects" sh -c 'pg_restore -U "$POSTGRES_USER" -d "$1" --no-owner --exit-on-error' sh "$source_db" <"$objects_dump"
{
    cat <<'SQL'
BEGIN;
INSERT INTO webmail_object_users(mailbox) VALUES (:'id') ON CONFLICT DO NOTHING;
CREATE TEMP TABLE restored (LIKE webmail_objects) ON COMMIT DROP;
COPY restored FROM STDIN;
SQL
    docker exec -i "$objects" sh -c 'psql -U "$POSTGRES_USER" -d "$1" -qtA -v ON_ERROR_STOP=1 -v source="$2" -v wanted="$3"' sh "$source_db" "$source_id" "$wanted" <<'SQL'
COPY (SELECT * FROM webmail_objects WHERE mailbox=:'source' AND collection = ANY(string_to_array(:'wanted', ','))) TO STDOUT;
SQL
    cat <<SQL
\.
WITH added AS (
    INSERT INTO webmail_objects SELECT :'id', collection, id, name, title, content_type, data, modified FROM restored
    ON CONFLICT DO NOTHING RETURNING 1
) SELECT 'webmail objects: ' || count(*) || ' of the ' || (SELECT count(*) FROM restored) || ' in the backup were missing' FROM added;
$end;
SQL
} | docker exec -i "$objects" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qtA -v ON_ERROR_STOP=1 -v id="$1"' sh "$account_id"
