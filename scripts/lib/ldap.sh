# shellcheck shell=bash
# The directory's nodes, for scripts that reach into them as root over
# ldapi:///. A single directory is one node; a replicated one is several
# (docker/ldap/entrypoint.sh). Data written to one node reaches the others
# by replication, but configuration (schema, access rules, the admin
# password) is each node's own, so scripts change it on every node.
#
#   ldap_nodes            the nodes, one per line, the first being the one
#                         to write data to
#   ldap_exec <node> ...  run a command in a node, with stdin
#
# Compose marks each directory container with the label elemta.ldap.node;
# Kubernetes pods carry app.kubernetes.io/name=elemta-ldap.

ldap_nodes() {
    if [ "${ELEMTA_STACK:-}" = k8s ]; then
        kubectl -n "${K8S_NAMESPACE:-elemta}" get pods -l app.kubernetes.io/name=elemta-ldap \
            --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort
        return
    fi
    local nodes
    nodes=$(docker ps --filter label=elemta.ldap.node --format '{{.Names}}' | sort)
    echo "${nodes:-elemta-ldap}"
}

ldap_exec() {
    local node=$1
    shift
    if [ "${ELEMTA_STACK:-}" = k8s ]; then
        kubectl -n "${K8S_NAMESPACE:-elemta}" exec -i "$node" -- "$@"
    else
        docker exec -i "$node" "$@"
    fi
}

ldap_first() { ldap_nodes | head -n 1; }
