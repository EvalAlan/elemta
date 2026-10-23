#!/bin/sh
# Checks that a backup from scripts/backup.sh restores, without touching the
# running stack: every file matches its checksum, the mailbox restores into
# throwaway containers and every message's body is there with its checksum
# (scripts/mailbox-restore-drill.sh), the directory loads into a throwaway
# directory server with as many entries as were exported, and the queue,
# configuration and secrets archives are readable and hold what a restore
# needs.
#
#   scripts/restore-drill.sh <backup directory>
set -eu
in=${1:?usage: $0 <backup directory>}
root=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$in/complete" ] || { echo "Backup is incomplete" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/lib/compose.sh
. "$root/scripts/lib/compose.sh"
image=${MAILBOX_IMAGE:-$(docker inspect -f '{{.Config.Image}}' "$(svc_container mailbox-server)")}
ldap_image=${LDAP_IMAGE:-$(docker inspect -f '{{.Config.Image}}' elemta-ldap)}
in=$(cd "$in" && pwd)

echo "== Checksums"
grep '^sha256 ' "$in/manifest" | while read -r _ sum file; do
    [ "$(sha256sum "$in/$file" | cut -d ' ' -f 1)" = "$sum" ] || { echo "Checksum differs: $file" >&2; exit 1; }
done

echo "== Mailbox"
MAILBOX_IMAGE=$image "$root/scripts/mailbox-restore-drill.sh" "$in/mailbox"

echo "== Directory"
want=$(sed -n 's/^ldap_entries=//p' "$in/manifest")
# Created the way restore.sh creates it, in a throwaway container.
got=$(docker run --rm --network none --user 0 --entrypoint sh -v "$in/ldap:/backup:ro" \
    -e LDAP_ADMIN_PASSWORD=drill -e LDAP_CONFIG_DIR=/tmp/c -e LDAP_DATA_DIR=/tmp/d -e LDAP_IMPORT=/backup/data.ldif "$ldap_image" -c '
    set -e
    elemta-ldap init >/dev/null
    slapcat -n 1 -F /tmp/c 2>/dev/null | grep -c "^dn: "')
[ "$got" = "$want" ] || { echo "Directory restored $got entries, the backup has $want" >&2; exit 1; }
echo "directory entries: $got"

echo "== MTA and secrets"
for f in mta/elemta_queue.tar.gz mta/elemta_config.tar.gz; do
    tar -tzf "$in/$f" >/dev/null
done
tar -tzf "$in/mta/elemta_config.tar.gz" | grep -q 'elemta.toml$' || { echo "No elemta.toml in the runtime configuration" >&2; exit 1; }
if [ -f "$in/secrets.tar.gz" ]; then
    list=$(tar -tzf "$in/secrets.tar.gz")
    for need in mailbox.env mailbox-postgres.env mailbox-tls/cert.pem; do
        echo "$list" | grep -q "^\.secrets/$need$" || { echo "Secrets archive lacks $need" >&2; exit 1; }
    done
else
    echo "secrets are encrypted (secrets.tar.gz.age); not opened"
fi
echo "Restore drill passed: $(sed -n 's/^created=//p' "$in/manifest"), $(sed -n 's/^version=//p' "$in/manifest")"
