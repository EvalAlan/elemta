#!/usr/bin/env bash
# Keeps the mail services' certificates in step with what is wanted, on the
# cloud dev server (docs/cloud-dev.md). Run by scripts/cloud-deploy.sh, a
# twice-daily timer, and a path unit when the admin console asks.
#
# Certificates come from two places:
#   - Caddy's Let's Encrypt certificates, for MAIL_DOMAIN, for mail.<domain>
#     of each of EXTRA_MAIL_DOMAINS ("configured"), and for the host names
#     the admin console requested ("requested");
#   - certificates uploaded in the admin console ("uploaded").
# MAIL_DOMAIN's goes to deployments/compose/.secrets/mailbox-tls/, every other
# one to mailbox-tls/sni/<host>/, which the mail services serve to clients
# asking for that host. Both re-read the files when they change, so nothing
# restarts. A host no longer wanted is removed from both Caddy and sni/.
#
# The admin console runs unprivileged and can only write into
# .secrets/cert-sync/requests/; everything it wrote is checked again here
# before use. The outcome goes to .secrets/cert-sync/status.json for the
# console to show.
#
# Exits non-zero while Caddy has no certificate for MAIL_DOMAIN yet. A host
# without one yet (its DNS hasn't moved here) is only reported, so it doesn't
# hold up the others. Prints "updated" when it replaced any files.
#
# --render-only writes Caddy's site names and stops: the deploy needs the
# Caddyfile before Caddy can start. --mta-sts-records <address> prints the DNS
# records MTA_STS_DOMAINS needs, changing nothing.
#
# MTA_STS_DOMAINS in cloud.env lists domains that publish an MTA-STS policy
# (RFC 8461), on a site of their own at mta-sts.<domain>. It's a list because
# Caddy keeps failing to get a certificate for a name with no DNS, and a name
# needs one whether or not anyone wants a policy. MTA_STS_MODE is testing, the
# default, enforce or none.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
secrets=$root/deployments/compose/.secrets
dir=$secrets/mailbox-tls
manage=$secrets/cert-sync
requests=$manage/requests
caddyfile=$secrets/cloud/caddy/Caddyfile
# shellcheck disable=SC1091
. "$secrets/cloud.env"
: "${MAIL_DOMAIN:?}"
issued=/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
changed=0
rejected=()

# A host name the scripts, sed and the Caddyfile can use unescaped: lowercase
# labels of letters, digits and inner hyphens, at least two of them.
valid_host() {
    [ ${#1} -le 253 ] && [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}
reject() { rejected+=("$1|$2"); }

configured=()
for d in ${EXTRA_MAIL_DOMAINS:-}; do
    configured+=("mail.$d")
done

requested=()
if [ -f "$requests/hosts" ]; then
    while IFS= read -r h || [ -n "$h" ]; do
        h=${h%%#*}
        h=${h//[[:space:]]/}
        [ -n "$h" ] || continue
        if ! valid_host "$h"; then
            reject "$h" "not a valid host name"
        elif [ "$h" = "$MAIL_DOMAIN" ] || [[ " ${configured[*]} ${requested[*]} " == *" $h "* ]]; then
            continue
        else
            requested+=("$h")
        fi
    done <"$requests/hosts"
fi

# Caddy obtains a certificate for every name on the webmail's site.
names=$MAIL_DOMAIN
for h in "${configured[@]}" "${requested[@]}"; do
    names="$names, $h"
done

# One policy serves every domain, since they all deliver to this server. It
# lists every mail host here, so it can't disagree with an MX pointing at any
# of them. A week's max_age only in enforce: senders keep following a policy
# that long, and testing is where mistakes should still be cheap.
mta_sts_mode=${MTA_STS_MODE:-testing}
case $mta_sts_mode in
enforce) mta_sts_age=604800 ;;
testing | none) mta_sts_age=86400 ;;
*)
    echo "cloud-sync-certs: MTA_STS_MODE must be enforce, testing or none, not '$mta_sts_mode'" >&2
    exit 1
    ;;
esac
mta_sts_policy="version: STSv1
mode: $mta_sts_mode"
for h in "$MAIL_DOMAIN" "${configured[@]}" "${requested[@]}"; do
    mta_sts_policy="$mta_sts_policy
mx: $h"
done
mta_sts_policy="$mta_sts_policy
max_age: $mta_sts_age"
# Senders refetch the policy only when this changes, so it comes from the
# policy itself and can't be forgotten.
mta_sts_id=$(printf '%s' "$mta_sts_policy" | sha256sum | cut -c1-20)
mta_sts_sites=()
for d in ${MTA_STS_DOMAINS:-}; do
    if valid_host "$d"; then
        mta_sts_sites+=("mta-sts.$d")
    else
        echo "cloud-sync-certs: '$d' in MTA_STS_DOMAINS isn't a domain name; skipping it" >&2
    fi
done

if [ "${1:-}" = --mta-sts-records ]; then
    for site in "${mta_sts_sites[@]}"; do
        d=${site#mta-sts.}
        printf '  %s.  A    %s\n' "$site" "${2:?an address for the A records}"
        printf '  _mta-sts.%s.  TXT  "v=STSv1; id=%s"\n' "$d" "$mta_sts_id"
    done
    exit 0
fi

sed -e "s|^{\$MAIL_DOMAIN} {|{\$MAIL_DOMAIN}${names#"$MAIL_DOMAIN"} {|" "$root/deployments/cloud/Caddyfile" >"$tmp/Caddyfile"
if ! grep -q "^{\$MAIL_DOMAIN}" "$tmp/Caddyfile"; then
    echo "cloud-sync-certs: the Caddyfile template no longer has the {\$MAIL_DOMAIN} site" >&2
    exit 1
fi
if [ ${#mta_sts_sites[@]} -gt 0 ]; then
    # Its own site, so these names serve the policy and nothing else: the
    # webmail's sign-in page has no business on them.
    {
        echo
        echo "# MTA-STS, from MTA_STS_DOMAINS (scripts/cloud-sync-certs.sh)."
        (IFS=,; echo "${mta_sts_sites[*]} {" | sed 's/,/, /g')
        printf '\theader -Server\n'
        printf '\t@policy path /.well-known/mta-sts.txt\n'
        printf '\thandle @policy {\n'
        printf '\t\theader Content-Type "text/plain; charset=utf-8"\n'
        printf '\t\trespond <<POLICY\n'
        printf '%s\n' "$mta_sts_policy" | sed 's/^/\t\t\t/'
        printf '\t\t\tPOLICY 200\n'
        printf '\t}\n'
        printf '\thandle {\n\t\trespond 404\n\t}\n'
        echo "}"
    } >>"$tmp/Caddyfile"
fi
if ! cmp -s "$tmp/Caddyfile" "$caddyfile"; then
    mkdir -p "$(dirname "$caddyfile")"
    # In place: Caddy's directory mount must see the same file.
    cat "$tmp/Caddyfile" >"$caddyfile"
    chmod 644 "$caddyfile"
    if [ "${1:-}" != --render-only ]; then
        # Retried, since a container just started may not be taking reloads.
        for i in $(seq 15); do
            docker exec elemta-caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 && break
            [ "$i" = 15 ] && { echo "cloud-sync-certs: Caddy didn't take the new Caddyfile; see docker logs elemta-caddy" >&2; exit 1; }
            sleep 2
        done
    fi
fi
[ "${1:-}" = --render-only ] && exit 0

# install source-cert source-key destination: puts a checked pair in place.
install_pair() {
    local cert=$1 key=$2 dest=$3
    if [ "$(openssl x509 -noout -pubkey -in "$cert" 2>/dev/null)" != "$(openssl pkey -pubout -in "$key" 2>/dev/null)" ]; then
        return 1
    fi
    mkdir -p "$dest"
    chmod 755 "$dest"
    if cmp -s "$cert" "$dest/cert.pem" && cmp -s "$key" "$dest/key.pem"; then
        return 0
    fi
    # The services run as uid 1001, not the host user; the directory above
    # this one is private to the host user, so the files themselves can be
    # readable.
    cp "$cert" "$tmp/cert.pem" && cp "$key" "$tmp/key.pem"
    chmod 644 "$tmp/cert.pem" "$tmp/key.pem"
    # Renames, so a reader never sees a half-written file. The key goes first:
    # a reader that catches the new key with the old certificate rejects the
    # pair and keeps serving, then takes both when the certificate changes too.
    mv "$tmp/key.pem" "$dest/.key.pem.new" && mv -f "$dest/.key.pem.new" "$dest/key.pem"
    mv "$tmp/cert.pem" "$dest/.cert.pem.new" && mv -f "$dest/.cert.pem.new" "$dest/cert.pem"
    changed=1
}

# from_caddy host destination: installs Caddy's certificate for host.
from_caddy() {
    docker exec elemta-caddy cat "$issued/$1/$1.crt" >"$tmp/caddy.crt" 2>/dev/null || return 1
    docker exec elemta-caddy cat "$issued/$1/$1.key" >"$tmp/caddy.key" 2>/dev/null || return 1
    install_pair "$tmp/caddy.crt" "$tmp/caddy.key" "$2" || {
        echo "cloud-sync-certs: certificate and key from Caddy for $1 do not match" >&2
        return 1
    }
}

# The default certificate is MAIL_DOMAIN's unless the console chose another of
# Caddy's names. MAIL_DOMAIN still gets its own below: the webmail's submission
# and LMTP check the public certificate against that name.
primary=$MAIL_DOMAIN
if [ -f "$requests/primary" ]; then
    IFS= read -r wanted <"$requests/primary" || true
    wanted=${wanted//[[:space:]]/}
    if [ -z "$wanted" ] || [ "$wanted" = "$MAIL_DOMAIN" ]; then
        :
    elif ! valid_host "$wanted"; then
        reject "$wanted" "not a valid host name"
    elif [[ " ${configured[*]} ${requested[*]} " != *" $wanted "* ]]; then
        reject "$wanted" "can't be the default: it has no Let's Encrypt certificate here"
    elif from_caddy "$wanted" "$tmp/primary"; then
        primary=$wanted
    else
        reject "$wanted" "can't be the default yet: no certificate from Caddy"
    fi
fi
from_caddy "$MAIL_DOMAIN" "$tmp/deployment" || { echo "cloud-sync-certs: no certificate for $MAIL_DOMAIN from Caddy yet" >&2; exit 1; }
changed=0
from_caddy "$primary" "$dir"

keep=() pending=()
if [ "$primary" != "$MAIL_DOMAIN" ]; then
    keep+=("$MAIL_DOMAIN")
    from_caddy "$MAIL_DOMAIN" "$dir/sni/$MAIL_DOMAIN"
fi
for h in "${configured[@]}" "${requested[@]}"; do
    keep+=("$h")
    from_caddy "$h" "$dir/sni/$h" || pending+=("$h")
done

uploaded=()
if [ -d "$requests/uploads" ]; then
    for up in "$requests/uploads"/*/; do
        [ -d "$up" ] || continue
        h=$(basename "$up")
        c=$up/cert.pem k=$up/key.pem
        if ! valid_host "$h"; then
            reject "$h" "not a valid host name"
        elif [ "$h" = "$MAIL_DOMAIN" ] || [[ " ${keep[*]} " == *" $h "* ]]; then
            reject "$h" "already has a Let's Encrypt certificate"
        elif [ ! -f "$c" ] || [ ! -f "$k" ]; then
            reject "$h" "the upload is incomplete"
        elif ! openssl x509 -noout -checkend 0 -in "$c" >/dev/null 2>&1; then
            reject "$h" "the certificate has expired or can't be read"
        elif ! openssl x509 -noout -checkhost "$h" -in "$c" 2>/dev/null | grep -q "does match"; then
            reject "$h" "the certificate doesn't name the host"
        elif ! install_pair "$c" "$k" "$dir/sni/$h"; then
            reject "$h" "the key doesn't match the certificate"
        else
            keep+=("$h")
            uploaded+=("$h")
        fi
    done
fi

# A host no longer configured, requested or uploaded stops being served.
if [ -d "$dir/sni" ]; then
    for old in "$dir/sni"/*/; do
        [ -d "$old" ] || continue
        name=$(basename "$old")
        case " ${keep[*]} " in *" $name "*) ;; *) rm -rf "$old"; changed=1 ;; esac
    done
fi

# Every value in it has been validated as a host name, and the reasons are
# fixed strings, so plain quoting is enough.
json_list() {
    local out="" x
    for x in "$@"; do out="$out${out:+, }\"$x\""; done
    printf '[%s]' "$out"
}
if [ -d "$manage" ]; then
    {
        printf '{\n  "applied_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '  "primary": "%s",\n' "$primary"
        printf '  "deployment": "%s",\n' "$MAIL_DOMAIN"
        printf '  "configured": %s,\n' "$(json_list "${configured[@]}")"
        printf '  "requested": %s,\n' "$(json_list "${requested[@]}")"
        printf '  "uploaded": %s,\n' "$(json_list "${uploaded[@]}")"
        printf '  "pending": %s,\n' "$(json_list "${pending[@]}")"
        printf '  "rejected": ['
        sep=""
        for r in "${rejected[@]}"; do
            n=${r%%|*}
            # A rejected name may be anything the console wrote; keep only
            # characters that are safe in JSON.
            n=${n//[^a-zA-Z0-9.*_-]/?}
            printf '%s{"name": "%s", "reason": "%s"}' "$sep" "$n" "${r#*|}"
            sep=", "
        done
        printf ']\n}\n'
    } >"$tmp/status.json"
    chmod 644 "$tmp/status.json"
    mv -f "$tmp/status.json" "$manage/status.json"
fi

for h in "${pending[@]}"; do
    echo "cloud-sync-certs: no certificate for $h from Caddy yet" >&2
done
for r in "${rejected[@]}"; do
    echo "cloud-sync-certs: ignored ${r%%|*}: ${r#*|}" >&2
done
if [ "$changed" = 1 ]; then
    echo updated
fi
