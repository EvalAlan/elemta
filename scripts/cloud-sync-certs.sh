#!/usr/bin/env bash
# Copies Caddy's Let's Encrypt certificate for MAIL_DOMAIN into
# deployments/compose/.secrets/mailbox-tls/, where the mailbox service and
# Elemta read it (docs/cloud-dev.md). Both re-read the files when they change,
# so a renewal needs no restart. Exits non-zero while Caddy has no certificate
# yet; prints "updated" when it replaced the files.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
secrets=$root/deployments/compose/.secrets
dir=$secrets/mailbox-tls
# shellcheck disable=SC1091
. "$secrets/cloud.env"
: "${MAIL_DOMAIN:?}"
src=/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$MAIL_DOMAIN

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
docker exec elemta-caddy cat "$src/$MAIL_DOMAIN.crt" >"$tmp/cert.pem"
docker exec elemta-caddy cat "$src/$MAIL_DOMAIN.key" >"$tmp/key.pem"
if [ "$(openssl x509 -noout -pubkey -in "$tmp/cert.pem")" != "$(openssl pkey -pubout -in "$tmp/key.pem")" ]; then
    echo "cloud-sync-certs: certificate and key from Caddy do not match" >&2
    exit 1
fi
if cmp -s "$tmp/cert.pem" "$dir/cert.pem" && cmp -s "$tmp/key.pem" "$dir/key.pem"; then
    exit 0
fi
# The services run as uid 1001, not the host user; the directory above this
# one is private to the host user, so the files themselves can be readable.
chmod 644 "$tmp/cert.pem" "$tmp/key.pem"
# Renames, so a reader never sees a half-written file. The key goes first: a
# reader that catches the new key with the old certificate rejects the pair
# and keeps serving, then takes both when the certificate changes too.
mv "$tmp/key.pem" "$dir/.key.pem.new" && mv -f "$dir/.key.pem.new" "$dir/key.pem"
mv "$tmp/cert.pem" "$dir/.cert.pem.new" && mv -f "$dir/.cert.pem.new" "$dir/cert.pem"
echo updated
