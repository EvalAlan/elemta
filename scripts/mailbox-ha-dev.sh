#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
storage="$root/deployments/compose/.secrets/mailbox-storage.env"
compose() {
    docker compose --env-file "$storage" \
        -f "$root/deployments/compose/docker-compose.mailbox-ha.yml" "$@"
}
case "${1:-ps}" in
    up)
        docker compose --env-file "$storage" \
            -f "$root/deployments/compose/docker-compose.mailbox.yml" build mailbox-a
        compose up -d --build etcd-a etcd-b etcd-c pg-a pg-b pg-c edge-a edge-b
        # Start the mailbox processes only once the strict commit policy can
        # succeed. A writable primary alone is insufficient for this lab.
        ready=false
        for attempt in $(seq 1 90); do
            if compose exec -T pg-a curl -fsS http://localhost:8008/cluster 2>/dev/null |
                python3 -c 'import json,sys; m=json.load(sys.stdin)["members"]; sys.exit(0 if sum(x["role"]=="quorum_standby" and x["state"]=="streaming" for x in m)==2 else 1)' 2>/dev/null; then
                ready=true
                break
            fi
            sleep 2
        done
        if [ "$ready" != true ]; then echo 'HA replication quorum did not converge.' >&2; exit 1; fi
        compose up --no-deps -d --force-recreate --wait --wait-timeout 90 mailbox-a mailbox-b
        ;;
    down) compose down ;;
    ps) compose ps ;;
    *) echo 'Usage: mailbox-ha-dev.sh up|down|ps' >&2; exit 2 ;;
esac
