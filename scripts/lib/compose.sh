# shellcheck shell=sh
# Containers of a Compose service. Scalable services have no fixed
# container name (Compose names them <project>-<service>-<n>), so scripts
# find them by the service label instead.
#
#   svc_containers <service>  every running container of the service
#   svc_container <service>   the first of them (or the service name, for a
#                             stack that still names the container so)

svc_containers() {
    docker ps --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' | sort
}

svc_container() {
    c=$(svc_containers "$1" | head -n 1)
    echo "${c:-$1}"
}

# The prefix of the stack's volume names (docker-compose.yml names them
# <prefix>_<volume>): ELEMTA_VOLUME_PREFIX from the environment or the given
# env file, else elemta. A stack created before the compose file named its
# project keeps compose_* volumes and sets the prefix to compose.
#
#   volume_prefix [env-file]
volume_prefix() {
    p=${ELEMTA_VOLUME_PREFIX:-}
    if [ -z "$p" ] && [ -n "${1:-}" ] && [ -f "$1" ]; then
        p=$(sed -n 's/^ELEMTA_VOLUME_PREFIX=//p' "$1" | tail -n 1)
    fi
    echo "${p:-elemta}"
}
