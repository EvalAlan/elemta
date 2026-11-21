#!/usr/bin/env bash
# Restores a mailbox backup into throwaway containers, beside the running
# stack and touching none of its data, then checks it: every body a
# message refers to must exist with its checksum.
#
#   scripts/mailbox-restore-drill.sh <backup directory>
#
# Restoring for real is the same steps against the stack's own volumes,
# with the mailbox replicas stopped.
#
# A backup made with BACKUP_BODIES=external has no bodies: they stayed in
# the stack's store. The drill then checks a random sample of the restored
# messages' bodies there (DRILL_BODY_SAMPLE, default 200), through a running
# mailbox replica, which holds the store's keys. It only reads: verify never
# deletes, and the cleanup that does runs only in the serving process. A
# body removed since the backup (a deleted message, after body_grace_hours)
# shows as missing unless the store kept its old version, so drill a backup
# when it's made.
set -eu
in=${1:?usage: $0 <backup directory>}
[ -f "$in/complete" ] || { echo "Backup is incomplete" >&2; exit 1; }
bodies=$(sed -n 's/^bodies=//p' "$in/manifest")
bodies=${bodies:-copy}
metadata_hash=$(sed -n 's/^metadata_sha256=//p' "$in/manifest")
[ "$(sha256sum "$in/metadata.dump" | cut -d ' ' -f 1)" = "$metadata_hash" ] || { echo "Metadata checksum differs" >&2; exit 1; }
base_hash=$(sed -n 's/^base_sha256=//p' "$in/manifest")
if [ -n "$base_hash" ]; then
    [ "$(sha256sum "$in/base.tar.gz" | cut -d ' ' -f 1)" = "$base_hash" ] || { echo "Base backup checksum differs" >&2; exit 1; }
fi
if [ "$bodies" = copy ]; then
    bodies_hash=$(sed -n 's/^bodies_sha256=//p' "$in/manifest")
    [ "$(sha256sum "$in/bodies.tar.gz" | cut -d ' ' -f 1)" = "$bodies_hash" ] || { echo "Bodies checksum differs" >&2; exit 1; }
fi
image=${MAILBOX_IMAGE:-elemta-mailbox:dev}
root="$(cd "$(dirname "$0")/.." && pwd)"
secrets="$root/deployments/compose/.secrets"
run=drill-$$
net=elemta-$run
dbc=elemta-$run-db
vol=elemta-$run-bodies
pgvol=elemta-$run-pg
pw=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)

basec=elemta-$run-base
basevol=elemta-$run-basevol

cleanup() {
    docker rm -f "$dbc" "$basec" >/dev/null 2>&1 || true
    docker volume rm "$vol" "$pgvol" "$basevol" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --internal "$net" >/dev/null
docker volume create "$vol" >/dev/null
docker volume create "$pgvol" >/dev/null
docker run -d --name "$dbc" --network "$net" -e POSTGRES_USER=mailbox -e POSTGRES_DB=mailbox \
    -e POSTGRES_PASSWORD="$pw" -v "$pgvol:/var/lib/postgresql/data" postgres:17-alpine >/dev/null
until docker exec "$dbc" pg_isready -U mailbox -d mailbox >/dev/null 2>&1; do sleep 1; done
sleep 2

echo "Restoring metadata"
docker exec -i "$dbc" pg_restore -U mailbox -d mailbox --no-owner --exit-on-error <"$in/metadata.dump"

# The base backup, when there is one, is what a point-in-time restore rolls
# forward with the archived WAL. It carries the WAL it needs to be
# consistent, so it must start on its own and hold the mail. It is taken
# seconds after the dump, so the counts can differ by what arrived or was
# deleted in between; an empty copy of a mailbox with mail is the failure.
if [ -n "$base_hash" ]; then
    echo "Starting the base backup"
    docker volume create "$basevol" >/dev/null
    docker run --rm -i --network none --user 0 --entrypoint sh -v "$basevol:/d" postgres:17-alpine \
        -c 'tar -xzf - -C /d && chown -R 70:70 /d && chmod 700 /d' <"$in/base.tar.gz"
    docker run -d --name "$basec" --network none -v "$basevol:/var/lib/postgresql/data" postgres:17-alpine \
        -c archive_mode=off >/dev/null
    ready=false
    for _ in $(seq 120); do
        if docker exec "$basec" pg_isready -q -U mailbox -d mailbox 2>/dev/null &&
            [ "$(docker exec "$basec" psql -U mailbox -d mailbox -tAc 'select not pg_is_in_recovery()' 2>/dev/null)" = t ]; then
            ready=true
            break
        fi
        sleep 1
    done
    $ready || { docker logs --tail 20 "$basec" >&2; echo "The base backup didn't start" >&2; exit 1; }
    base_count=$(docker exec "$basec" psql -U mailbox -d mailbox -tAc "select count(*) from mailbox_messages")
    dump_count=$(docker exec "$dbc" psql -U mailbox -d mailbox -tAc "select count(*) from mailbox_messages")
    echo "base backup: $base_count messages (dump: $dump_count)"
    [ "$base_count" -gt 0 ] || [ "$dump_count" -eq 0 ] || { echo "The base backup holds no messages" >&2; exit 1; }
    docker rm -f "$basec" >/dev/null
fi

# The bodies are checked below with keys the live stack holds, which proves
# nothing about the backup's own copy of them. MAILBOX_BODY_KEYS_FILE names
# that copy (restore-drill.sh takes it from the backup's secrets); every key
# the restored metadata recorded must be in it, or a restore from this backup
# alone couldn't read the mail.
if [ -n "${MAILBOX_BODY_KEYS_FILE:-}" ]; then
    echo "Checking the backup's body keys against its metadata"
    docker run --rm --network "$net" --env-file "$MAILBOX_BODY_KEYS_FILE" \
        -e ELEMTA_MAILBOX_DATABASE_DSN="postgres://mailbox:$pw@$dbc:5432/mailbox?sslmode=disable" \
        "$image" mailbox check-keys
elif [ "$(docker exec "$dbc" psql -U mailbox -d mailbox -tAc 'select count(*) from mailbox_body_keys')" != 0 ]; then
    echo "Note: the bodies are encrypted and MAILBOX_BODY_KEYS_FILE isn't set, so the backup's own keys aren't checked"
fi

if [ "$bodies" = external ]; then
    # shellcheck source=SCRIPTDIR/lib/compose.sh
    . "$root/scripts/lib/compose.sh"
    mailbox=${MAILBOX_CONTAINER:-$(svc_container mailbox-server)}
    live_net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$mailbox" | head -n 1)
    # The throwaway database joins the stack's network so the replica can
    # reach it; removing it at the end takes it off again.
    docker network connect "$live_net" "$dbc"
    echo "Verifying a sample of bodies in the stack's store, through $mailbox"
    docker exec -e "${MAILBOX_DSN_ENV:-ELEMTA_MAILBOX_DATABASE_DSN}=postgres://mailbox:$pw@$dbc:5432/mailbox?sslmode=disable" "$mailbox" \
        /app/elemta mailbox verify --config /etc/elemta/mailbox.toml --sample "${DRILL_BODY_SAMPLE:-200}"
    got=$(docker exec "$dbc" psql -U mailbox -d mailbox -tAc "select count(*) from mailbox_messages")
    echo "restored messages: $got"
    echo "Restore drill passed (bodies checked in place)"
    exit 0
fi
# The bodies are in a volume here whatever store they came from, and the
# engine refuses metadata that names another store.
docker exec "$dbc" psql -q -U mailbox -d mailbox -c "UPDATE mailbox_bodies SET store='file:/var/lib/elemta/bodies'"
echo "Restoring bodies"
docker run --rm -i --network none --user 0 --entrypoint sh -v "$vol:/bodies" "$image" \
    -c 'tar -C /bodies -xzf - && chown -R 1001:1001 /bodies' <"$in/bodies.tar.gz"

echo "Verifying"
# An encrypted store refuses to open without its key, so a drill proves the
# key restores too.
body_keys=()
[ ! -f "$secrets/mailbox-body-keys.env" ] || body_keys=(--env-file "$secrets/mailbox-body-keys.env")
docker run --rm --network "$net" --env-file "$secrets/mailbox.env" "${body_keys[@]}" \
    -e PGHOST="$dbc" -e PGUSER=mailbox -e PGPASSWORD="$pw" -e PGDATABASE=mailbox -e PGSSLMODE=disable \
    -v "$root/config/mailbox-main.toml:/etc/elemta/mailbox.toml:ro" \
    -v "$secrets/mailbox-tls/cert.pem:/etc/elemta/tls/cert.pem:ro" \
    -v "$secrets/mailbox-tls/key.pem:/etc/elemta/tls/key.pem:ro" \
    -v "$vol:/var/lib/elemta/bodies" "$image" mailbox verify --config /etc/elemta/mailbox.toml

got=$(docker exec "$dbc" psql -U mailbox -d mailbox -tAc "select count(*) from mailbox_messages")
echo "restored messages: $got"
echo "Restore drill passed"
