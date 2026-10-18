#!/bin/sh
# An isolated project keeps experimental mailbox data away from live Maildirs.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
storage="$root/deployments/compose/.secrets/mailbox-storage.env"
if [ ! -f "$storage" ]; then
    echo 'Run make ensure-dev-secrets first.' >&2
    exit 1
fi
compose() {
    docker compose --env-file "$storage" \
        -f "$root/deployments/compose/docker-compose.mailbox.yml" "$@"
}
case "${1:-ps}" in
    up) compose up -d --build --wait metadata mailbox-a mailbox-b edge ;;
    s3)
        # Separate volumes do not translate existing body keys. This mode is
        # for a fresh database or accounts whose bodies were migrated first.
        compose --profile s3 up -d object-store
        echo 'S3 fixture started. Select s3 only for a fresh/migrated metadata store.'
        ;;
    webmail) compose --profile webmail up -d webmail ;;
    down) compose --profile s3 --profile webmail down ;;
    ps) compose --profile s3 --profile webmail ps ;;
    *) echo 'Usage: mailbox-dev.sh up|s3|webmail|down|ps' >&2; exit 2 ;;
esac
