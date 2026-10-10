#!/usr/bin/env bash
# Deploy one image tag of the production stack on this host, and roll back
# to the previous tag if it does not come up healthy.
#
#   remote-deploy.sh <tag>
#
# Run from the deploy directory (DEPLOY_PATH), which holds
# docker-compose.prod.yml and the operator's .env. The workflow copies this
# script and the compose file there and runs it over SSH; it works the same
# by hand.
#
# What "healthy" means here: both Elemta containers report healthy to Docker
# (the SMTP port answers, /api/health answers), and the MX port on this host
# returns a 220 banner. The last check is the one that matters, because a
# container can be healthy behind a port mapping that is wrong.
#
# Rollback restores the previous tag in .env and brings it back up. If there
# is no previous tag (first deploy), a failed deploy is left as it is for the
# operator to look at; there is nothing to go back to.

set -euo pipefail

TAG="${1:?usage: remote-deploy.sh <image-tag>}"
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env"
STATE_FILE=".deployed-tag"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-360}"

if ! [[ "$TAG" =~ ^[A-Za-z0-9_.-]{1,128}$ ]]; then
    echo "refusing tag with unexpected characters: $TAG" >&2
    exit 2
fi
[ -f "$COMPOSE_FILE" ] || { echo "no $COMPOSE_FILE in $(pwd)" >&2; exit 2; }
touch "$ENV_FILE"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

# set_tag rewrites only the ELEMTA_TAG line; the rest of .env is the operator's.
set_tag() {
    local tmp
    tmp="$(mktemp "$ENV_FILE.XXXXXX")"
    grep -v '^ELEMTA_TAG=' "$ENV_FILE" > "$tmp" || true
    printf 'ELEMTA_TAG=%s\n' "$1" >> "$tmp"
    chmod --reference="$ENV_FILE" "$tmp" 2>/dev/null || chmod 600 "$tmp"
    mv "$tmp" "$ENV_FILE"
}

smtp_port() {
    local p
    p="$(grep -E '^SMTP_PORT=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
    echo "${p:-25}"
}

# healthy waits for both Elemta containers to report healthy and the MX port
# to greet, or gives up after HEALTH_TIMEOUT seconds.
healthy() {
    local deadline=$((SECONDS + HEALTH_TIMEOUT)) port
    port="$(smtp_port)"
    while [ "$SECONDS" -lt "$deadline" ]; do
        local s1 s2
        s1="$(docker inspect -f '{{.State.Health.Status}}' elemta 2>/dev/null || echo missing)"
        s2="$(docker inspect -f '{{.State.Health.Status}}' elemta-web 2>/dev/null || echo missing)"
        if [ "$s1" = healthy ] && [ "$s2" = healthy ]; then
            local banner
            banner="$(timeout 10 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port && head -c 3 <&3" 2>/dev/null || true)"
            if [ "$banner" = "220" ]; then
                echo "healthy: elemta=$s1 elemta-web=$s2, port $port greets with 220"
                return 0
            fi
            echo "containers healthy, port $port not greeting yet"
        else
            echo "waiting: elemta=$s1 elemta-web=$s2"
        fi
        sleep 5
    done
    return 1
}

previous=""
[ -f "$STATE_FILE" ] && previous="$(cat "$STATE_FILE")"
echo "deploying $TAG (previous: ${previous:-none})"

# Pull before touching .env: if the pull fails, nothing has changed and a
# later restart still runs the tag that was working. ELEMTA_SKIP_PULL=1 is
# for hosts where the image was loaded by hand (docker load).
if [ "${ELEMTA_SKIP_PULL:-}" != "1" ]; then
    ELEMTA_TAG="$TAG" compose pull --quiet elemta elemta-web
fi
set_tag "$TAG"

# A failed `up` (bad .env, port in use) takes the same rollback path as a
# failed health check rather than exiting with the new tag recorded.
if compose up -d --remove-orphans && healthy; then
    echo "$TAG" > "$STATE_FILE"
    echo "deployed $TAG"
    exit 0
fi

echo "::error::$TAG did not start or did not become healthy within ${HEALTH_TIMEOUT}s" >&2
compose ps >&2 || true
compose logs --tail 80 elemta elemta-web >&2 || true

if [ -z "$previous" ] || [ "$previous" = "$TAG" ]; then
    echo "no earlier working tag to roll back to; leaving $TAG in place for inspection" >&2
    exit 1
fi

echo "rolling back to $previous" >&2
set_tag "$previous"
if compose up -d --remove-orphans && healthy; then
    echo "rolled back to $previous; the failed tag was $TAG" >&2
else
    echo "::error::rollback to $previous is not healthy either; needs a person" >&2
fi
exit 1
