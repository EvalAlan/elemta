#!/bin/sh
# Restores a mailbox backup into throwaway containers, beside the running
# stack and touching none of its data, then checks it: every body a
# message refers to must exist with its checksum.
#
#   scripts/mailbox-restore-drill.sh <backup directory>
#
# Restoring for real is the same steps against the stack's own volumes,
# with the mailbox replicas stopped.
set -eu
in=${1:?usage: $0 <backup directory>}
[ -f "$in/complete" ] || { echo "Backup is incomplete" >&2; exit 1; }
metadata_hash=$(sed -n 's/^metadata_sha256=//p' "$in/manifest")
bodies_hash=$(sed -n 's/^bodies_sha256=//p' "$in/manifest")
[ "$(sha256sum "$in/metadata.dump" | cut -d ' ' -f 1)" = "$metadata_hash" ] || { echo "Metadata checksum differs" >&2; exit 1; }
[ "$(sha256sum "$in/bodies.tar.gz" | cut -d ' ' -f 1)" = "$bodies_hash" ] || { echo "Bodies checksum differs" >&2; exit 1; }
image=${MAILBOX_IMAGE:-elemta-mailbox:dev}
root="$(cd "$(dirname "$0")/.." && pwd)"
secrets="$root/deployments/compose/.secrets"
run=drill-$$
net=elemta-$run
dbc=elemta-$run-db
vol=elemta-$run-bodies
pgvol=elemta-$run-pg
pw=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)

cleanup() {
    docker rm -f "$dbc" >/dev/null 2>&1 || true
    docker volume rm "$vol" "$pgvol" >/dev/null 2>&1 || true
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
