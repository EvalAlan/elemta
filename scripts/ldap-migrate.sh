#!/bin/bash
# Moves the directory from the previous LDAP image's volumes into the
# current image's. Needed once, when upgrading from v0.5.3 or earlier;
# scripts/cloud-deploy.sh runs it, and it does nothing when there is nothing
# to move (a new install, or a directory already moved).
#
# The previous image ran OpenLDAP 2.4 and this one runs 2.6, whose database
# format differs, so the move is an export and an import: the previous
# image's own slapcat reads its volumes, and the new image creates the
# directory from that export with a fresh configuration. The access rules,
# admin password and service-account passwords are then applied as on any
# deploy, and the entry counts compared.
#
# The old volumes (ldap_data, ldap_config) are not touched. Rolling back is
# checking out the previous release and starting it as before; once the new
# directory has proved itself, remove them with `docker volume rm`.
#
# Logins that need the directory fail for the minute or so this takes; mail
# arriving meanwhile is deferred by the MTA and retried by the sender.
#
#   scripts/ldap-migrate.sh
#
# Settings: ELEMTA_COMPOSE_PROJECT (default elemta), ELEMTA_VOLUME_PREFIX (default from .secrets/cloud.env, else elemta), ELEMTA_TAG (default the
# one in .secrets/cloud.env; selects the release images).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
compose_dir=$root/deployments/compose
secrets=$compose_dir/.secrets
project=${ELEMTA_COMPOSE_PROJECT:-elemta}
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
volumes=$(volume_prefix "$secrets/cloud.env")
# The image that wrote the old volumes, by the digest the release overlay
# pinned, so its slapcat reads them exactly as it wrote them.
legacy_image=osixia/openldap:latest@sha256:3f68751292b43564a2586fc29fb7337573e2dad692b92d4e78e49ad5c22e567b

files=(-f "$compose_dir/docker-compose.yml")
env=()
if [ -f "$secrets/cloud.env" ]; then
    env=(--env-file "$secrets/cloud.env")
    files+=(-f "$compose_dir/docker-compose.cloud.yml")
    ELEMTA_TAG=${ELEMTA_TAG:-$(sed -n 's/^ELEMTA_TAG=//p' "$secrets/cloud.env")}
fi
if [ -n "${ELEMTA_TAG:-}" ]; then
    export ELEMTA_TAG
    files+=(-f "$compose_dir/docker-compose.release.yml")
fi
dc() { docker compose -p "$project" "${env[@]}" "${files[@]}" "$@"; }
# holds <volume> <path>: the volume exists and has <path> in it.
holds() {
    docker volume inspect "${volumes}_$1" >/dev/null 2>&1 &&
        docker run --rm --network none -v "${volumes}_$1:/v:ro" --entrypoint test "$legacy_image" -e "/v/$2"
}

if holds ldap_slapd cn=config.ldif; then
    echo "ldap-migrate: the directory is already on the current image."
    exit 0
fi
if ! holds ldap_data data.mdb; then
    echo "ldap-migrate: no directory from the previous image to move."
    exit 0
fi

tmp=$(mktemp -d "$secrets/.ldap-migrate.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chmod 700 "$tmp"

echo "ldap-migrate: stopping the directory and exporting it with the previous image"
dc stop elemta-ldap >/dev/null 2>&1 || true
docker run --rm --network none --user 0 --entrypoint slapcat \
    -v "${volumes}_ldap_data:/var/lib/ldap" -v "${volumes}_ldap_config:/etc/ldap/slapd.d" \
    -v "$tmp:/out" "$legacy_image" -n 1 -l /out/data.ldif
want=$(grep -c '^dn: ' "$tmp/data.ldif" || true)
[ "$want" -gt 0 ] || { echo "ldap-migrate: the export is empty; nothing changed" >&2; exit 1; }

echo "ldap-migrate: creating the directory on the current image from $want entries"
dc up --no-start --no-deps elemta-ldap
image=$(docker inspect -f '{{.Config.Image}}' elemta-ldap)
docker run --rm --network none --user 0 --env-file "$secrets/ldap-admin.env" \
    -v "${volumes}_ldap_db:/var/lib/ldap" -v "${volumes}_ldap_slapd:/etc/ldap/slapd.d" \
    -v "$tmp/data.ldif:/import/data.ldif:ro" "$image" init
dc up -d --no-deps elemta-ldap
for _ in $(seq 60); do
    docker exec elemta-ldap ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b dc=example,dc=com -s base dn >/dev/null 2>&1 && break
    sleep 2
done

# The configuration is new, so the rules and passwords a deploy applies are
# applied here too; without the rules the services couldn't read anything.
"$root/scripts/ldap-schema.sh"
"$root/scripts/ldap-admin-password.sh"
"$root/scripts/ldap-service-accounts.sh"

# Every exported entry must be there, but for ou=mailgroups, which
# ldap-schema.sh above removes on purpose when it is empty. There can be more:
# the service accounts above, on a directory that predates them.
dns() { perl -0pe 's/\n //g' | sed -n 's/^dn: //p' | sort; }
exported() { dns <"$tmp/data.ldif" | { grep -vxF "ou=mailgroups,dc=example,dc=com" || true; }; }
missing=$(comm -23 <(exported) <(docker exec elemta-ldap slapcat -n 1 | dns))
[ -z "$missing" ] || { printf 'ldap-migrate: missing from the new directory:\n%s\n' "$missing" >&2; exit 1; }
echo "ldap-migrate: done, all $want entries moved. The old volumes ${volumes}_ldap_data and ${volumes}_ldap_config are untouched."
