#!/usr/bin/env bash
# Deploys the stack on the cloud dev server (docs/cloud-dev.md). Run on the
# server from the repository root; safe to re-run after every code update.
#
# Needs deployments/compose/.secrets/cloud.env with at least:
#   MAIL_DOMAIN=dev.example.net     the host's name and its mail domain
#   DKIM_SELECTOR=dev2026           optional
#   EXTRA_MAIL_DOMAINS="example.org"  optional: more mail domains, separated
#                                   by spaces, each with its own mail host
#                                   mail.<domain>, certificate and DKIM key
#   MAILBOX_BODY_GRACE_HOURS=168    optional: how long a deleted message's
#                                   body is kept before cleanup removes it
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
extra_domains=${EXTRA_MAIL_DOMAINS:-}
# They go into sed expressions, TOML and the Caddyfile unescaped.
for x in $extra_domains; do
    case $x in
    *[!a-z0-9.-]* | .* | *. | *..* | "$MAIL_DOMAIN")
        echo "cloud-deploy: '$x' in EXTRA_MAIL_DOMAINS isn't a lowercase domain name other than MAIL_DOMAIN" >&2
        exit 1
        ;;
    esac
done
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
    # Rewritten in place, not renamed over: mailbox.toml is a file bind
    # mount, which keeps showing the old inode to a running container.
    cat "$out.tmp" >"$out"
    rm -f "$out.tmp"
}

step "Configuration for $MAIL_DOMAIN${extra_domains:+ and $extra_domains}"
# Container users (uid 1001) must traverse these; .secrets itself stays 0700.
mkdir -p "$secrets/cloud/config" "$secrets/cloud/dkim" "$secrets/cloud/caddy" "$secrets/mailbox-tls/sni"
chmod 755 "$secrets/cloud" "$secrets/cloud/config" "$secrets/cloud/dkim" "$secrets/cloud/caddy" "$secrets/mailbox-tls" "$secrets/mailbox-tls/sni"
# The admin console, which runs as the container user, writes its
# certificate requests into requests/ and reads the sync's status.json next
# to it; it can't write anything the sync doesn't check again.
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 755 "$secrets/cert-sync"
sudo install -d -o 1001 -g 1001 -m 755 "$secrets/cert-sync/requests"
# Left by an earlier layout, where the console wrote here directly.
sudo rm -f "$secrets/cert-sync/request"
d=$MAIL_DOMAIN
domains_toml="\"$d\""
for x in $extra_domains; do
    domains_toml="$domains_toml, \"$x\""
done
render "$root/config/elemta.toml" "$secrets/cloud/config/elemta.toml" \
    "s|^hostname = .*|hostname = \"$d\"|" \
    "s|^local_domains = .*|local_domains = [$domains_toml]|" \
    's|^mode = "lmtp"|mode = "split"|' \
    "s|^cert_file = .*|cert_file = \"/app/tls/cert.pem\"|" \
    "s|^key_file = .*|key_file = \"/app/tls/key.pem\"|" \
    '/^\[tls\]/,/^\[/{s|^key_file = .*|&\nsni_cert_dir = "/app/tls/sni"|}' \
    "s|^lmtp_tls_ca_file = .*|lmtp_tls_ca_file = \"\"|" \
    "s|^lmtp_tls_server_name = .*|lmtp_tls_server_name = \"$d\"|" \
    "s|^submission_addr = .*|submission_addr = \"$d:2588\"|" \
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
# Each extra domain signs as itself: DMARC alignment needs d= to be exactly
# the From domain, and a strict (adkim=s) policy rejects a parent or sibling.
for x in $extra_domains; do
    cat >>"$secrets/cloud/config/elemta.toml" <<EOF

[[plugins.dkim.domains]]
domain = "$x"
selector = "$DKIM_SELECTOR"
private_key_path = "/app/dkim/$DKIM_SELECTOR.$x.key"
EOF
done
mailbox_edits=(
    "s|^default_domain = .*|default_domain = \"$d\"|"
    "s|^hostname = .*|hostname = \"$d\"|"
    's|^tls_key = .*|&\ntls_sni_dir = "/etc/elemta/tls/sni"|'
)
# Message bodies go to an S3 bucket when .secrets/object-storage.env names
# one, and to the mailbox_bodies volume otherwise. Choose before the first
# account exists: the mailbox service refuses to start on mail stored under
# another storage identity, and there is no migration between them.
s3_env=$secrets/object-storage.env
s3_keys=$secrets/mailbox-s3.env
if [ -f "$s3_env" ]; then
    # shellcheck disable=SC1090
    . "$s3_env"
    : "${S3_ENDPOINT:?set S3_ENDPOINT in $s3_env}" "${S3_BUCKET:?set S3_BUCKET in $s3_env}"
    : "${S3_REGION:?set S3_REGION in $s3_env}" "${S3_ACCESS_KEY_ID:?set S3_ACCESS_KEY_ID in $s3_env}"
    : "${S3_SECRET_ACCESS_KEY:?set S3_SECRET_ACCESS_KEY in $s3_env}"
    # They go into a sed expression and TOML strings unescaped.
    for v in "$S3_ENDPOINT" "$S3_BUCKET" "$S3_REGION"; do
        case $v in *[!A-Za-z0-9.:-]*) echo "cloud-deploy: '$v' in $s3_env isn't a plain host, bucket or region name" >&2; exit 1 ;; esac
    done
    mailbox_edits+=("/^\[bodies\]/,/^\[/{s|^driver = .*|driver = \"s3\"|;s|^endpoint = .*|endpoint = \"$S3_ENDPOINT\"|;s|^bucket = .*|bucket = \"$S3_BUCKET\"|;s|^region = .*|region = \"$S3_REGION\"|;s|^secure = false|secure = true|}")
    (
        umask 077
        printf 'ELEMTA_MAILBOX_S3_ACCESS_KEY=%s\nELEMTA_MAILBOX_S3_SECRET_KEY=%s\n' \
            "$S3_ACCESS_KEY_ID" "$S3_SECRET_ACCESS_KEY" >"$s3_keys"
    )
else
    rm -f "$s3_keys"
fi
render "$root/config/mailbox-main.toml" "$secrets/cloud/mailbox.toml" "${mailbox_edits[@]}"
# Without collection a deleted message's body stays in storage forever. The
# grace must outlast the oldest metadata backup you might restore, which still
# names the body.
cat >>"$secrets/cloud/mailbox.toml" <<EOF

# Added by scripts/cloud-deploy.sh.
[maintenance]
garbage_collection = true
body_grace_hours = ${MAILBOX_BODY_GRACE_HOURS:-168}
EOF
chmod 644 "$secrets/cloud/config/elemta.toml" "$secrets/cloud/mailbox.toml"
# Caddy's site names: the primary, each extra domain's mail host, and the
# hosts requested in the admin console. The certificate sync keeps them
# current from then on.
"$root/scripts/cloud-sync-certs.sh" --render-only

dkim_key=$secrets/cloud/dkim/$DKIM_SELECTOR.key
dkim_keys=("$dkim_key")
for x in $extra_domains; do
    dkim_keys+=("$secrets/cloud/dkim/$DKIM_SELECTOR.$x.key")
done
for k in "${dkim_keys[@]}"; do
    # sudo: an existing key belongs to the container user, not this one.
    if ! sudo test -f "$k"; then
        step "DKIM key $(basename "$k" .key)"
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$k" 2>/dev/null
    fi
    # Elemta refuses a signing key that anyone but its owner can read, so it
    # belongs to the container user (uid 1001), not the host user.
    sudo chown 1001:1001 "$k"
    sudo chmod 600 "$k"
done

if [ -n "${ELEMTA_TAG:-}" ]; then
    step "Release images ($ELEMTA_TAG)"
    dc pull --ignore-buildable --quiet
    dc build elemta-dns
else
    step "Building images"
    dc build
fi

step "Directory and certificate"
# Once, on hosts that still have the previous directory image's data; a
# no-op everywhere else.
"$root/scripts/ldap-migrate.sh"
dc up -d elemta-ldap elemta-caddy
# A running Caddy doesn't notice a re-rendered Caddyfile (new mail hosts).
# Retried, since a container just started may not be taking reloads yet.
for i in $(seq 15); do
    docker exec elemta-caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 && break
    [ "$i" = 15 ] && { echo "cloud-deploy: Caddy didn't take the new Caddyfile; see docker logs elemta-caddy" >&2; exit 1; }
    sleep 2
done
for _ in $(seq 60); do
    docker exec elemta-ldap ldapsearch -Q -Y EXTERNAL -H ldapi:/// \
        -b "dc=example,dc=com" -s base dn >/dev/null 2>&1 && break
    sleep 2
done
# The mail schema and the branches entries live in, created empty: no demo
# accounts with published passwords on a public server.
"$root/scripts/ldap-schema.sh"
"$root/scripts/ldap-admin-password.sh"
"$root/scripts/ldap-service-accounts.sh"

for i in $(seq 90); do
    "$root/scripts/cloud-sync-certs.sh" >/dev/null 2>&1 && break
    [ "$i" = 90 ] && { echo "cloud-deploy: no certificate from Caddy after 3 minutes; see docker logs elemta-caddy" >&2; exit 1; }
    sleep 2
done
"$root/scripts/cloud-sync-certs.sh"
# An extra host whose DNS hasn't moved here yet has no certificate; it is
# served the primary one until a later sync (the timer, or a re-run) finds it.
for x in $extra_domains; do
    for i in $(seq 30); do
        [ -f "$secrets/mailbox-tls/sni/mail.$x/cert.pem" ] && break
        [ "$i" = 30 ] && { echo "cloud-deploy: no certificate for mail.$x yet; check its A record, then re-run" >&2; break; }
        sleep 2
        "$root/scripts/cloud-sync-certs.sh" >/dev/null 2>&1 || true
    done
done

step "Starting the stack"
ELEMTA_CONFIG_RESEED=true dc up -d --remove-orphans
# The services copy the rendered configuration only when their container is
# new (scripts/prepare-config.sh), and the mailbox servers read theirs only
# at start; Compose recreates a container only when its definition changes.
# Without this, a re-run that only changed the rendering (a new domain)
# deployed nothing.
ELEMTA_CONFIG_RESEED=true dc up -d --no-deps --force-recreate elemta elemta-admin elemta-webmail mailbox-server

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
# The admin console's Sync now writes the request file; this runs the same
# service when it does.
sudo tee "$unit.path" >/dev/null <<EOF
[Unit]
Description=Elemta certificate sync on request from the admin console

[Path]
PathModified=$secrets/cert-sync/requests/request
Unit=elemta-cert-sync.service

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now elemta-cert-sync.timer elemta-cert-sync.path >/dev/null 2>&1

dkim_p=$(sudo openssl pkey -in "$dkim_key" -pubout -outform der 2>/dev/null | base64 -w0)
ip4=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
cat <<EOF

==> Done. DNS records for $d (check with: dig +short TXT $d):
  $d.                     TXT  "v=spf1 a mx -all"
  $DKIM_SELECTOR._domainkey.$d.  TXT  "v=DKIM1; k=rsa; p=$dkim_p"
  _imaps._tcp.$d.         SRV  0 1 993 $d.
  _submission._tcp.$d.    SRV  0 1 587 $d.
  Reverse DNS of $ip4 -> $d   (set at the hosting provider)
EOF
for x in $extra_domains; do
    p=$(sudo openssl pkey -in "$secrets/cloud/dkim/$DKIM_SELECTOR.$x.key" -pubout -outform der 2>/dev/null | base64 -w0)
    cat <<EOF

DNS records for $x. Publish the DKIM and SPF records, and the A record for
mail.$x, before moving the MX: a strict DMARC policy rejects unsigned mail.
  mail.$x.                A    $ip4
  $DKIM_SELECTOR._domainkey.$x.  TXT  "v=DKIM1; k=rsa; p=$p"
  $x.                     TXT  "v=spf1 mx -all"   (or add ip4:$ip4 to the existing record)
  _imaps._tcp.$x.         SRV  0 1 993 mail.$x.
  _submission._tcp.$x.    SRV  0 1 587 mail.$x.
  $x.                     MX   10 mail.$x.   (last)
EOF
done
cat <<EOF

Next: create the domain's first account (docs/cloud-dev.md, "Accounts").
EOF
