#!/bin/bash
# Updates Compose services one container at a time, so a service with
# several containers keeps serving while it moves to a new image or
# configuration.
#
#   scripts/rolling-update.sh [service ...]
#
# Compose itself recreates every container of a service at once. Instead,
# for each scalable service this starts as many new containers as are
# running, waits for them to be healthy, then removes the old ones one at a
# time; the load balancers in front (HAProxy, Caddy) follow the change. A
# service with a fixed container name, which can only run once, is simply
# recreated, as before.
#
# The compose files and project are the same as the deploy's: set
# ELEMTA_TAG for the release images, as scripts/cloud-deploy.sh does.
#
# Settings: ELEMTA_COMPOSE_PROJECT (default compose), ELEMTA_TAG.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
compose_dir=$root/deployments/compose
secrets=$compose_dir/.secrets
project=${ELEMTA_COMPOSE_PROJECT:-compose}
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"

files=(-f "$compose_dir/docker-compose.yml")
env=()
if [ -f "$secrets/cloud.env" ]; then
    env=(--env-file "$secrets/cloud.env")
    files+=(-f "$compose_dir/docker-compose.cloud.yml")
    ELEMTA_TAG=${ELEMTA_TAG:-$(sed -n 's/^ELEMTA_TAG=//p' "$secrets/cloud.env")}
fi
[ -z "${ELEMTA_TAG:-}" ] || {
    export ELEMTA_TAG
    files+=(-f "$compose_dir/docker-compose.release.yml")
}
[ ! -f "$compose_dir/docker-compose.scale.yml" ] || [ "${ELEMTA_SCALE:-}" != 1 ] || files+=(-f "$compose_dir/docker-compose.scale.yml")
dc() { docker compose -p "$project" "${env[@]}" "${files[@]}" "$@"; }

healthy() {
    local c=$1
    for _ in $(seq 100); do
        case $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c" 2>/dev/null) in
        healthy | running) return 0 ;;
        esac
        sleep 3
    done
    echo "rolling-update: $c didn't become healthy" >&2
    return 1
}

services=("$@")
[ ${#services[@]} -gt 0 ] || services=(elemta-ldap elemta-mailbox-server elemta elemta-webmail elemta-web)

for svc in "${services[@]}"; do
    mapfile -t old < <(svc_containers "$svc")
    fixed=$(dc config --format json | python3 -c "import json,sys; print(json.load(sys.stdin)['services'].get('$svc',{}).get('container_name',''))" 2>/dev/null || true)
    if [ -n "$fixed" ] || [ ${#old[@]} -eq 0 ]; then
        echo "rolling-update: $svc: recreating"
        dc up -d --no-deps "$svc" >/dev/null
        for c in $(svc_containers "$svc"); do healthy "$c"; done
        continue
    fi
    n=${#old[@]}
    echo "rolling-update: $svc: starting $n new beside $n old"
    dc up -d --no-deps --no-recreate --scale "$svc=$((2 * n))" "$svc" >/dev/null
    for c in $(svc_containers "$svc"); do
        printf '%s\n' "${old[@]}" | grep -qx "$c" && continue
        healthy "$c"
    done
    for c in "${old[@]}"; do
        echo "rolling-update: $svc: removing $c"
        docker stop -t 30 "$c" >/dev/null
        docker rm "$c" >/dev/null
        sleep 2
    done
    echo "rolling-update: $svc: $(svc_containers "$svc" | wc -l) containers on the new version"
done
