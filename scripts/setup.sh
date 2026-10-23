#!/usr/bin/env bash
# Elemta setup wizard (`make install`).
#
# Walks through installing Elemta on this machine, either:
#
#   - a development stack, to try it out (make install-dev), or
#   - an internet-facing mail server for a real domain: it checks the host
#     and DNS, makes the host changes the stack's security depends on (each
#     one explained and confirmed), deploys with scripts/cloud-deploy.sh,
#     and creates the first admin console login and mailbox.
#
# It can be re-run: answers default to what is already configured, and every
# step is idempotent.
#
# Usage: scripts/setup.sh [--dev | --server] [--domain NAME] [--full] [--yes] [--check]
#   --yes    accept every default and confirm every step, for unattended runs.
#   --check  server mode: run the host, DNS and Docker checks, change nothing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
secrets=$root/deployments/compose/.secrets
env_file=$secrets/cloud.env
mode="" domain="" full=0 assume_yes=0 check_only=0

while [ $# -gt 0 ]; do
    case "$1" in
    --dev) mode=dev ;;
    --server) mode=server ;;
    --domain) domain=${2:?--domain needs a name}; shift ;;
    --full) full=1 ;;
    --yes | -y) assume_yes=1 ;;
    --check) check_only=1 mode=server ;;
    -h | --help) sed -n '2,/^set /p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 0 ;;
    *) echo "setup: unknown option $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

# ---- output ------------------------------------------------------------------
if [ -t 1 ]; then
    bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' yellow=$'\e[33m' blue=$'\e[34m' off=$'\e[0m'
else
    bold='' dim='' red='' green='' yellow='' blue='' off=''
fi
section() { printf '\n%s━━ %s %s\n' "$blue$bold" "$*" "$off"; }
ok() { printf '  %s✓%s %s\n' "$green" "$off" "$*"; }
warn() { printf '  %s!%s %s\n' "$yellow" "$off" "$*"; }
fail() { printf '  %s✗%s %s\n' "$red" "$off" "$*"; }
note() { printf '    %s%s%s\n' "$dim" "$*" "$off"; }
die() { printf '\n%sSetup stopped:%s %s\n' "$red$bold" "$off" "$*" >&2; exit 1; }

# ask VAR "question" default: reads from the terminal even when piped.
ask() {
    local var=$1 question=$2 default=${3:-} answer
    if [ "$assume_yes" = 1 ]; then
        printf -v "$var" '%s' "$default"
        return
    fi
    read -r -p "  $question${default:+ [$default]}: " answer </dev/tty
    printf -v "$var" '%s' "${answer:-$default}"
}

# confirm "question" y|n: the default is taken on Enter, and by --yes.
confirm() {
    local question=$1 default=${2:-y} answer hint="[Y/n]"
    [ "$default" = n ] && hint="[y/N]"
    if [ "$assume_yes" = 1 ]; then
        return 0
    fi
    read -r -p "  $question $hint " answer </dev/tty
    answer=${answer:-$default}
    [[ $answer =~ ^[Yy] ]]
}

as_root() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

has() { command -v "$1" >/dev/null 2>&1; }

# ---- checks shared by both modes --------------------------------------------
check_prerequisites() {
    section "Checking this machine"
    local missing=0
    for tool in docker openssl python3 git; do
        if has "$tool"; then ok "$tool"; else fail "$tool is not installed"; missing=1; fi
    done
    if has docker && docker compose version >/dev/null 2>&1; then
        ok "docker compose $(docker compose version --short 2>/dev/null)"
    else
        fail "Docker Compose v2 (the 'docker compose' plugin) is not installed"
        missing=1
    fi
    if has docker && ! docker info >/dev/null 2>&1; then
        fail "this user can't reach Docker; add it to the docker group, then sign in again"
        missing=1
    fi
    [ "$missing" = 0 ] || die "install what's missing above, then run make install again."

    local mem_mb disk_gb
    mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    disk_gb=$(df -Pk "$root" | awk 'NR==2 {print int($4/1048576)}')
    if [ "$mem_mb" -ge 3500 ]; then ok "memory: ${mem_mb} MB"; else warn "memory: ${mem_mb} MB. 4 GB is recommended; ClamAV alone needs about 1.5 GB."; fi
    if [ "$disk_gb" -ge 20 ]; then ok "free disk: ${disk_gb} GB"; else warn "free disk: ${disk_gb} GB. Mail, scanner signatures and images need room; 20 GB or more is recommended."; fi
}

# ---- development --------------------------------------------------------------
setup_dev() {
    section "Development stack"
    note "Runs on this machine with test domains (example.com) and test accounts."
    note "Nothing is exposed beyond this machine's network."
    if [ "$full" = 0 ] && confirm "Include ClamAV, Rspamd and Roundcube? They need about 2 GB more memory." n; then
        full=1
    fi
    local target=install-dev
    [ "$full" = 1 ] && target=install-dev-full
    confirm "Run 'make $target' now?" y || die "nothing changed."
    make -C "$root" "$target"
}

# ---- server -------------------------------------------------------------------
public_ipv4() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}'
}
default_iface() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}'
}
is_private_ipv4() {
    [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.) ]]
}
dns_lookup() { # type name: prints answers, one per line
    if has dig; then
        dig +short "$1" "$2" 2>/dev/null
    elif [ "$1" = A ]; then
        getent ahostsv4 "$2" 2>/dev/null | awk '{print $1}' | sort -u
    fi
}

choose_domain() {
    section "Your mail domain"
    note "Mail addresses will be name@DOMAIN, and DOMAIN is also this server's host name"
    note "(webmail at https://DOMAIN, IMAP and SMTP at DOMAIN). Use a domain or subdomain"
    note "whose mail is not handled anywhere else, for example mail.example.org."
    local current=""
    if [ -f "$env_file" ]; then
        current=$(sed -n 's/^MAIL_DOMAIN=//p' "$env_file" | head -1)
    fi
    [ -n "$domain" ] || ask domain "Mail domain" "${current:-$(hostname -f 2>/dev/null || hostname)}"
    domain=$(printf '%s' "$domain" | tr 'A-Z' 'a-z')
    [[ $domain =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]] || die "'$domain' isn't a valid domain name."
    ok "mail domain: $domain"
}

check_network() {
    section "Network and DNS"
    ip4=$(public_ipv4)
    if [ -z "$ip4" ]; then
        die "no IPv4 default route; a mail server needs a public IPv4 address."
    elif is_private_ipv4 "$ip4"; then
        warn "this machine's address, $ip4, is private (behind NAT)"
        note "Forward ports 25, 80, 443, 587, 993, 143 and 110 to it, and use the public"
        note "address in DNS. The checks below compare DNS with the address you enter."
        ask ip4 "Public IPv4 address" ""
        [ -n "$ip4" ] || die "a public IPv4 address is needed."
    else
        ok "public IPv4: $ip4"
    fi

    local a mx ptr dns_ok=1
    a=$(dns_lookup A "$domain" | tr '\n' ' ')
    if [[ " $a " == *" $ip4 "* ]]; then ok "A record: $domain → $ip4"; else fail "A record: $domain → ${a:-nothing}; it must point at $ip4"; dns_ok=0; fi
    if has dig; then
        mx=$(dns_lookup MX "$domain" | awk '{print $2}' | sed 's/\.$//' | tr '\n' ' ')
        if [[ " $mx " == *" $domain "* ]]; then ok "MX record: $domain"; else warn "MX record: ${mx:-none}; add MX 10 $domain. so other servers deliver here"; fi
        ptr=$(dig +short -x "$ip4" 2>/dev/null | sed 's/\.$//' | head -1)
        if [ "$ptr" = "$domain" ]; then ok "reverse DNS: $ip4 → $domain"; else warn "reverse DNS: $ip4 → ${ptr:-nothing}; set it to $domain at your hosting provider, or outbound mail will be rejected"; fi
    else
        warn "dig isn't installed, so MX and reverse DNS aren't checked (install bind-utils or dnsutils)"
    fi
    if [ "$dns_ok" = 0 ]; then
        note "Let's Encrypt can't issue a certificate until the A record points here."
        confirm "Continue anyway?" n || die "fix the DNS record, then run make install again."
    fi

    if timeout 8 bash -c 'exec 3<>/dev/tcp/gmail-smtp-in.l.google.com/25' 2>/dev/null; then
        ok "outbound port 25 is open"
    else
        warn "outbound port 25 is blocked; many hosting providers block it until you ask them to lift it"
    fi

    local busy=""
    for port in 25 80 443 587 993 143 110; do
        if ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && ! docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$port->"; then
            busy="$busy $port"
        fi
    done
    if [ -n "$busy" ]; then
        fail "already in use by another program:$busy"
        die "stop whatever listens on those ports (often postfix, sendmail or a web server), then run make install again."
    fi
    ok "ports 25, 80, 443, 587, 993, 143 and 110 are free"
}

# Docker's userland proxy makes every client connecting over IPv6 appear to
# come from the Docker gateway, a private address the MTA trusts to relay.
# With it on, the server is an open relay. Not optional.
secure_docker() {
    section "Docker"
    local daemon=/etc/docker/daemon.json
    if [ -f "$daemon" ] && python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("userland-proxy") is False else 1)' "$daemon" 2>/dev/null; then
        ok "userland proxy is off"
        return
    fi
    warn "Docker's userland proxy is on"
    if [ "$check_only" = 1 ]; then
        note "Deploying requires turning it off; setup offers to do that."
        return
    fi
    note "With it on, clients connecting over IPv6 look like they come from inside the"
    note "Docker network, which the mail server trusts to relay: an open relay."
    note "This sets \"userland-proxy\": false in $daemon and restarts Docker."
    confirm "Turn it off now?" y || die "the server can't be deployed safely with the userland proxy on."
    as_root python3 - "$daemon" <<'EOF'
import json, os, sys
path = sys.argv[1]
config = json.load(open(path)) if os.path.exists(path) and os.path.getsize(path) else {}
config["userland-proxy"] = False
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(config, f, indent=2)
EOF
    as_root systemctl restart docker
    ok "userland proxy turned off; Docker restarted"
}

secure_firewall() {
    section "Firewall"
    local ports="25 80 443 587 993 143 110"
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        note "firewalld is running. This opens SSH, SMTP (25, 587), IMAP (993, 143),"
        note "POP3 (110) and HTTP/HTTPS (80, 443) in its default zone."
        if confirm "Open them?" y; then
            for svc in ssh smtp smtp-submission imaps http https; do as_root firewall-cmd -q --permanent --add-service="$svc"; done
            for p in 143 110; do as_root firewall-cmd -q --permanent --add-port="$p/tcp"; done
            as_root firewall-cmd -q --reload
            ok "firewalld allows ssh and $ports"
        fi
    elif has ufw && as_root ufw status 2>/dev/null | grep -q 'Status: active'; then
        note "ufw is running. This allows SSH and ports $ports."
        if confirm "Allow them?" y; then
            as_root ufw allow OpenSSH >/dev/null
            for p in $ports; do as_root ufw allow "$p/tcp" >/dev/null; done
            ok "ufw allows ssh and $ports"
        fi
    else
        warn "no host firewall (firewalld or ufw) is running"
        note "Turn one on and allow SSH and $ports; see docs/cloud-dev.md."
    fi

    # Docker publishes ports with its own rules, which the host firewall never
    # sees. This guard drops internet traffic to any published port except the
    # public ones, so a mistake in a compose file can't expose a database.
    has nft || { warn "nft isn't installed, so the Docker port guard is skipped"; return; }
    local iface admin_rule=""
    iface=$(default_iface)
    note "The Docker port guard drops internet traffic on $iface to every published"
    note "container port except $ports."
    confirm "Install the Docker port guard?" y || return
    if [ -n "${admin_ip:-}" ]; then
        admin_rule="    iifname \"$iface\" meta l4proto tcp ct status dnat ct original proto-dst 8025 ip saddr $admin_ip counter accept"
    fi
    as_root tee /etc/nftables/docker-guard.nft >/dev/null <<EOF
#!/usr/sbin/nft -f
# Written by scripts/setup.sh. Docker publishes ports with its own DNAT rules,
# which the host firewall never sees; this drops internet traffic to any
# published container port except the public mail and web ones. It matches the
# port the client dialled, so 993 -> 10993 is judged by 993.
table inet docker_guard
delete table inet docker_guard
table inet docker_guard {
  set public_ports { type inet_service; elements = { 25, 80, 110, 143, 443, 587, 993 } }
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
$admin_rule
    iifname "$iface" ct status dnat ct original proto-dst != @public_ports counter drop
  }
}
EOF
    as_root tee /etc/systemd/system/docker-guard.service >/dev/null <<'EOF'
[Unit]
Description=Restrict internet access to Docker published ports
After=network-pre.target firewalld.service
Before=docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables/docker-guard.nft
ExecReload=/usr/sbin/nft -f /etc/nftables/docker-guard.nft
ExecStop=/usr/sbin/nft delete table inet docker_guard

[Install]
WantedBy=multi-user.target
EOF
    as_root nft -c -f /etc/nftables/docker-guard.nft || die "the guard's rules didn't validate; nothing was loaded."
    as_root systemctl daemon-reload
    as_root systemctl enable docker-guard >/dev/null 2>&1
    as_root systemctl restart docker-guard
    ok "Docker port guard active on $iface"
}

choose_admin_access() {
    section "Admin console access"
    note "The admin console controls the whole server. By default it is reachable only"
    note "over SSH:  ssh -L 8025:127.0.0.1:8025 you@$domain  then http://localhost:8025"
    admin_ip=""
    if confirm "Also allow it directly over HTTPS from one IP address (https://$domain:8025)?" n; then
        ask admin_ip "IPv4 address to allow" ""
        [[ $admin_ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "'$admin_ip' isn't an IPv4 address."
        ok "admin console allowed from $admin_ip"
    else
        ok "admin console over SSH only"
    fi
}

write_settings() {
    mkdir -p "$secrets"
    chmod 700 "$secrets"
    touch "$env_file"
    chmod 600 "$env_file"
    set_env() { # key value: replace or append, keeping everything else
        if grep -q "^$1=" "$env_file"; then sed -i "s|^$1=.*|$1=$2|" "$env_file"; else echo "$1=$2" >>"$env_file"; fi
    }
    set_env MAIL_DOMAIN "$domain"
    if [ -n "$admin_ip" ]; then
        set_env ELEMTA_ADMIN_BIND_IP 0.0.0.0
        set_env ELEMTA_ADMIN_ALLOWED_IP "$admin_ip"
    else
        sed -i '/^ELEMTA_ADMIN_BIND_IP=/d; /^ELEMTA_ADMIN_ALLOWED_IP=/d' "$env_file"
    fi
}

first_accounts() {
    section "First accounts"
    make -C "$root" --no-print-directory bootstrap-admin
    note "That is the admin console login, not a mailbox."
    local address name
    if confirm "Create your first mailbox now?" y; then
        ask address "Mailbox address" "you@$domain"
        ask name "Display name" "${address%@*}"
        note "You'll be asked for its password."
        docker exec -it elemta-admin /app/elemta -c /app/runtime-config/elemta.toml \
            provision create-account "$address" --name "$name" ||
            warn "the mailbox wasn't created; see docs/cloud-dev.md, Accounts"
    fi
}

setup_server() {
    choose_domain
    check_network
    if [ "$check_only" = 1 ]; then
        secure_docker
        section "Check complete"
        note "Nothing was changed. Run make install to set the server up."
        return
    fi
    choose_admin_access
    secure_docker
    secure_firewall

    section "Ready to deploy"
    note "Domain:        $domain ($ip4)"
    note "Public ports:  25, 587 (SMTP), 993, 143 (IMAP), 110 (POP3), 80, 443 (webmail)"
    note "Admin console: ${admin_ip:+https://$domain:8025 from $admin_ip, and }SSH tunnel"
    note "This builds the images and starts the stack; the first run takes several minutes."
    confirm "Deploy now?" y || die "nothing deployed. Settings so far are kept; run make install to continue."
    write_settings
    "$root/scripts/cloud-deploy.sh"
    first_accounts

    section "Done"
    ok "Webmail:       https://$domain"
    ok "Mail apps:     $domain, IMAP 993 or 143, SMTP 587 (Thunderbird sets itself up)"
    ok "Admin console: ssh -L 8025:127.0.0.1:8025 $(id -un)@$domain, then http://localhost:8025"
    note "Publish the DNS records printed above (SPF, DKIM, and the SRV records), and"
    note "set reverse DNS for $ip4 to $domain. Guides: docs/cloud-dev.md, docs/user-guide.md."
}

# ---- main ---------------------------------------------------------------------
printf '%s\n' "$bold" "  Elemta setup" "$off"
note "A mail server, mailbox server, webmail and admin console, installed together."

check_prerequisites
if [ -z "$mode" ]; then
    section "What are you setting up?"
    note "1) A development stack on this machine, to try Elemta out"
    note "2) A mail server for a real domain, on an internet-facing host"
    ask choice "Choose 1 or 2" 1
    case "$choice" in 1) mode=dev ;; 2) mode=server ;; *) die "choose 1 or 2." ;; esac
fi
case "$mode" in
dev) setup_dev ;;
server) setup_server ;;
esac
