#!/usr/bin/env bash
# Deploys the stack on the cloud dev server (docs/cloud-dev.md). Run on the
# server from the repository root; safe to re-run after every code update.
#
# Needs deployments/compose/.secrets/cloud.env with at least:
#   MAIL_DOMAIN=dev.example.net     the host's name and its mail domain
#   DKIM_SELECTOR=dev2026           optional
#   ELEMTA_TAG=v0.5.0               optional: run that release's images from
#                                   ghcr.io, pinned and hardened
#                                   (docker-compose.release.yml), instead of
#                                   building this checkout. Production uses
#                                   this; see docs/production-compose.md.
#
# Re-running takes the rendered configuration again (ELEMTA_CONFIG_RESEED), so
# settings saved in the admin console are replaced; make lasting changes in
# this script's rendering instead.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
compose_dir=$root/deployments/compose
secrets=$compose_dir/.secrets
env_file=$secrets/cloud.env

if [ ! -f "$env_file" ]; then
    echo "cloud-deploy: create $env_file with MAIL_DOMAIN= first" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$env_file"
: "${MAIL_DOMAIN:?set MAIL_DOMAIN in $env_file}"
DKIM_SELECTOR=${DKIM_SELECTOR:-dev2026}
caddy_ip=${ELEMTA_CADDY_IP:-10.253.53.80}

files=(-f "$compose_dir/docker-compose.yml" -f "$compose_dir/docker-compose.cloud.yml")
if [ -n "${ELEMTA_TAG:-}" ]; then
    files+=(-f "$compose_dir/docker-compose.release.yml")
fi
dc() { docker compose --env-file "$env_file" "${files[@]}" "$@"; }
step() { printf '\n==> %s\n' "$*"; }

# Service credentials, and a self-signed placeholder certificate the mail
# services start with until the real one is copied over it.
step "Service credentials"
"$root/scripts/dev-secrets.sh"

# render template output sed-expression...
# Every expression must change the file: a template that has drifted fails
# here instead of quietly deploying, say, the example.com test domains.
render() {
    local src=$1 out=$2 e before
    shift 2
    cp "$src" "$out.tmp"
    for e in "$@"; do
        before=$(cksum <"$out.tmp")
        sed -i -e "$e" "$out.tmp"
        if [ "$(cksum <"$out.tmp")" = "$before" ]; then
            echo "cloud-deploy: '$e' matched nothing in $src" >&2
            rm -f "$out.tmp"
            exit 1
        fi
    done
    mv "$out.tmp" "$out"
}

step "Configuration for $MAIL_DOMAIN"
# Container users (uid 1001) must traverse these; .secrets itself stays 0700.
mkdir -p "$secrets/cloud/config" "$secrets/cloud/dkim"
chmod 755 "$secrets/cloud" "$secrets/cloud/config" "$secrets/cloud/dkim" "$secrets/mailbox-tls"
d=$MAIL_DOMAIN
render "$root/config/elemta.toml" "$secrets/cloud/config/elemta.toml" \
    "s|^hostname = .*|hostname = \"$d\"|" \
    "s|^local_domains = .*|local_domains = [\"$d\"]|" \
    's|^mode = "lmtp"|mode = "split"|' \
    "s|^cert_file = .*|cert_file = \"/app/tls/cert.pem\"|" \
    "s|^key_file = .*|key_file = \"/app/tls/key.pem\"|" \
    "s|^lmtp_tls_ca_file = .*|lmtp_tls_ca_file = \"\"|" \
    "s|^lmtp_tls_server_name = .*|lmtp_tls_server_name = \"$d\"|" \
    "s|^submission_addr = .*|submission_addr = \"$d:2587\"|" \
    "s|^insecure_skip_verify = true|insecure_skip_verify = false|" \
    "s|^secure_cookies = false|secure_cookies = true|" \
    "s|^recovery_url = .*|recovery_url = \"https://$d\"|" \
    "s|^recovery_sender = .*|recovery_sender = \"noreply@$d\"|" \
    "s|^recovery_smtp_user = .*|recovery_smtp_user = \"noreply@$d\"|" \
    '/^\[plugins\.dkim\]/,/^\[/{s|^sign = false|sign = true|;/^domains = \[\]/d}'
# [webmail] is the template's last table, so these keys land in it; the DKIM
# array of tables names its full path and may follow anywhere.
cat >>"$secrets/cloud/config/elemta.toml" <<EOF
# Added by scripts/cloud-deploy.sh. Caddy is the only proxy.
trusted_proxies = ["$caddy_ip/32"]

[[plugins.dkim.domains]]
domain = "$d"
selector = "$DKIM_SELECTOR"
private_key_path = "/app/dkim/$DKIM_SELECTOR.key"
EOF
render "$root/config/mailbox-main.toml" "$secrets/cloud/mailbox.toml" \
    "s|^default_domain = .*|default_domain = \"$d\"|" \
    "s|^hostname = .*|hostname = \"$d\"|"
chmod 644 "$secrets/cloud/config/elemta.toml" "$secrets/cloud/mailbox.toml"

dkim_key=$secrets/cloud/dkim/$DKIM_SELECTOR.key
if [ ! -f "$dkim_key" ]; then
    step "DKIM key ($DKIM_SELECTOR)"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dkim_key" 2>/dev/null
fi
# Elemta refuses a signing key that anyone but its owner can read, so it
# belongs to the container user (uid 1001), not the host user.
sudo chown 1001:1001 "$dkim_key"
sudo chmod 600 "$dkim_key"

if [ -n "${ELEMTA_TAG:-}" ]; then
    step "Release images ($ELEMTA_TAG)"
    dc pull --ignore-buildable --quiet
    dc build elemta-dns
else
    step "Building images"
    dc build
fi

step "Directory and certificate"
dc up -d elemta-ldap elemta-caddy
for _ in $(seq 60); do
    docker exec elemta-ldap ldapsearch -Q -Y EXTERNAL -H ldapi:/// \
        -b "dc=example,dc=com" -s base dn >/dev/null 2>&1 && break
    sleep 2
done
if ! docker exec elemta-ldap ldapsearch -LLL -o ldif-wrap=no -Y EXTERNAL -H ldapi:/// \
    -b cn=schema,cn=config '(objectClass=olcSchemaConfig)' olcAttributeTypes 2>/dev/null |
    grep -q "NAME 'mailAlternateAddress'"; then
    docker exec -i elemta-ldap ldapadd -Y EXTERNAL -H ldapi:/// <"$root/docker/ldap/10-mail-schema.ldif" >/dev/null
fi
# The containers the dev stack fills from fixtures, created empty: no demo
# accounts with published passwords on a public server.
for ou in people groups mailgroups domains; do
    if ! docker exec elemta-ldap ldapsearch -Q -Y EXTERNAL -H ldapi:/// \
        -b "ou=$ou,dc=example,dc=com" -s base dn >/dev/null 2>&1; then
        printf 'dn: ou=%s,dc=example,dc=com\nobjectClass: organizationalUnit\nou: %s\n' "$ou" "$ou" |
            docker exec -i elemta-ldap ldapadd -Q -Y EXTERNAL -H ldapi:/// >/dev/null
    fi
done
"$root/scripts/ldap-admin-password.sh"
"$root/scripts/ldap-service-accounts.sh"

for i in $(seq 90); do
    "$root/scripts/cloud-sync-certs.sh" >/dev/null 2>&1 && break
    [ "$i" = 90 ] && { echo "cloud-deploy: no certificate from Caddy after 3 minutes; see docker logs elemta-caddy" >&2; exit 1; }
    sleep 2
done
"$root/scripts/cloud-sync-certs.sh"

step "Starting the stack"
ELEMTA_CONFIG_RESEED=true dc up -d --remove-orphans

step "Certificate renewals"
unit=/etc/systemd/system/elemta-cert-sync
sudo tee "$unit.service" >/dev/null <<EOF
[Unit]
Description=Copy the renewed Let's Encrypt certificate to the Elemta mail services
After=docker.service

[Service]
Type=oneshot
User=$(id -un)
ExecStart=$root/scripts/cloud-sync-certs.sh
EOF
sudo tee "$unit.timer" >/dev/null <<EOF
[Unit]
Description=Twice-daily Elemta certificate sync

[Timer]
OnCalendar=*-*-* 03,15:17:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now elemta-cert-sync.timer >/dev/null 2>&1

dkim_p=$(sudo openssl pkey -in "$dkim_key" -pubout -outform der 2>/dev/null | base64 -w0)
ip4=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
cat <<EOF

==> Done. DNS records for $d (check with: dig +short TXT $d):
  $d.                     TXT  "v=spf1 a mx -all"
  $DKIM_SELECTOR._domainkey.$d.  TXT  "v=DKIM1; k=rsa; p=$dkim_p"
  _imaps._tcp.$d.         SRV  0 1 993 $d.
  _submission._tcp.$d.    SRV  0 1 587 $d.
  Reverse DNS of $ip4 -> $d   (set at the hosting provider)

Next: create the domain's first account (docs/cloud-dev.md, "Accounts").
EOF
