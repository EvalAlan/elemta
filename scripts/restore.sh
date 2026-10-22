#!/usr/bin/env bash
# Restores a backup from scripts/backup.sh into this host's stack, replacing
# its mail, directory, queue and runtime configuration. Destructive: run
# scripts/restore-drill.sh on the backup first.
#
#   scripts/restore.sh <backup directory> --confirm
#
# On a new host, check out the same release, then run this: it puts the
# secrets back first (they hold the passwords and keys everything else
# needs), then the data. On a host that has its own .secrets they are kept
# and the backup's are left alone, unless ELEMTA_RESTORE_SECRETS=true.
#
# Mail that arrives while it runs isn't lost: the MTA is stopped first, so
# sending servers queue it and retry.
#
# Settings: ELEMTA_COMPOSE_PROJECT (default compose), ELEMTA_TAG (as for
# scripts/cloud-deploy.sh: set it to restore onto the release images).
set -euo pipefail
in=${1:?usage: $0 <backup directory> --confirm}
[ "${2:-}" = --confirm ] || { echo "restore: this replaces the stack's data; add --confirm" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
compose_dir=$root/deployments/compose
secrets=$compose_dir/.secrets
project=${ELEMTA_COMPOSE_PROJECT:-compose}
in=$(cd "$in" && pwd)
[ -f "$in/complete" ] || { echo "restore: backup is incomplete" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

step "Checksums"
grep '^sha256 ' "$in/manifest" | while read -r _ sum file; do
    [ "$(sha256sum "$in/$file" | cut -d ' ' -f 1)" = "$sum" ] || { echo "restore: checksum differs: $file" >&2; exit 1; }
done

if [ ! -d "$secrets" ] || [ "${ELEMTA_RESTORE_SECRETS:-}" = true ]; then
    step "Secrets"
    [ -f "$in/secrets.tar.gz" ] || { echo "restore: decrypt secrets.tar.gz.age into the backup first (age -d)" >&2; exit 1; }
    docker run --rm --network none --user 0 --entrypoint tar -v "$compose_dir:/c" -i alpine:3.22 -C /c -xzf - <"$in/secrets.tar.gz"
fi
env_file=$secrets/cloud.env
files=(-f "$compose_dir/docker-compose.yml" -f "$compose_dir/docker-compose.cloud.yml")
[ -z "${ELEMTA_TAG:-}" ] || files+=(-f "$compose_dir/docker-compose.release.yml")
dc() { docker compose -p "$project" --env-file "$env_file" "${files[@]}" "$@"; }

step "Stopping mail services"
dc stop elemta elemta-web elemta-webmail elemta-mailbox elemta-mailbox-a elemta-mailbox-b elemta-ldap
dc up -d elemta-mailbox-db
until docker exec elemta-mailbox-db sh -c 'pg_isready -q -U "$POSTGRES_USER"'; do sleep 1; done
image=$(docker inspect -f '{{.Config.Image}}' elemta-mailbox-a)
ldap_image=$(docker inspect -f '{{.Config.Image}}' elemta-ldap)
# load <volume> <archive> [owner]: replace a volume's contents.
load() {
    docker run --rm -i --network none --user 0 --entrypoint sh -v "${project}_$1:/v" "$image" \
        -c "find /v -mindepth 1 -delete && tar -C /v -xzf - ${3:+&& chown -R $3 /v}" <"$2"
}

step "Mailbox metadata"
docker exec -i elemta-mailbox-db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --exit-on-error' <"$in/mailbox/metadata.dump"
step "Message bodies"
load mailbox_bodies "$in/mailbox/bodies.tar.gz" 1001:1001

step "Directory"
# Created afresh from the entries, as on a new install: the configuration
# comes from the image and the access rules and passwords from the deploy
# scripts once it runs, so a backup taken under the previous directory image
# restores the same way as a current one.
docker run --rm --network none --user 0 --entrypoint sh --env-file "$secrets/ldap-admin.env" \
    -v "${project}_ldap_slapd:/etc/ldap/slapd.d" -v "${project}_ldap_db:/var/lib/ldap" \
    -v "$in/ldap/data.ldif:/import/data.ldif:ro" "$ldap_image" \
    -c 'find /etc/ldap/slapd.d /var/lib/ldap -mindepth 1 -delete && elemta-ldap init'

step "MTA queue and runtime configuration"
load elemta_queue "$in/mta/elemta_queue.tar.gz" 1001:1001
load elemta_config "$in/mta/elemta_config.tar.gz" 1001:1001

step "Starting the stack"
# The restored runtime configuration is kept, not reseeded from the host.
ELEMTA_CONFIG_RESEED=false dc up -d
for c in elemta-ldap elemta-mailbox-a elemta-mailbox-b elemta-node0 elemta-webmail elemta-web; do
    for _ in $(seq 100); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)" = healthy ] && break
        sleep 3
    done
    echo "$c $(docker inspect -f '{{.State.Health.Status}}' "$c")"
    if [ "$c" = elemta-ldap ]; then
        "$root/scripts/ldap-schema.sh"
        "$root/scripts/ldap-admin-password.sh"
        "$root/scripts/ldap-service-accounts.sh"
    fi
done
echo "Restored $(sed -n 's/^created=//p' "$in/manifest") ($(sed -n 's/^version=//p' "$in/manifest"))"
