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
