#!/usr/bin/env bash
# Applies abuse protection's blocks to nftables, so a blocked address is dropped
# before it reaches a service (docs/abuse-protection.md). Run as root by
# elemta-abuse-firewall.timer on the Compose host.
#
# The plan comes out of a container, and this runs as root, so nothing in it is
# trusted: every line is checked here, and only plain addresses and numbers
# reach nft. If the plan can't be read, or is wrong, the firewall stays as it
# is, and its entries expire on their own.
#
# Only client ports are covered. Port 25 is left out on purpose: a block for
# guessing passwords shouldn't lose mail from every server sharing the address.
set -euo pipefail

table=elemta_abuse
ports="80, 110, 143, 443, 587, 993, 8025"
max_entries=20000
container=${ELEMTA_ABUSE_CONTAINER:-elemta-admin}
host=$(hostname)

# plan: "mode log|apply|off", then "allow <net>" and "block <target> <seconds>".
plan_source() {
    if [ -n "${ELEMTA_ABUSE_PLAN_FILE:-}" ]; then
        cat "$ELEMTA_ABUSE_PLAN_FILE"
    else
        docker exec "$container" /app/elemta abuse firewall-plan
    fi
}

report() {
    [ -z "${ELEMTA_ABUSE_PLAN_FILE:-}" ] || return 0
    docker exec "$container" /app/elemta abuse firewall-report --host "$host" --mode "$1" \
        --entries "$2" --dropped "$3" --error "${4:-}" >/dev/null 2>&1 || true
}

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
ipv6='^[0-9a-fA-F:]{2,39}(/[0-9]{1,3})?$'

valid_ip() {
    local v=$1 o
    if [[ $v =~ $ipv4 ]]; then
        local a=${v%/*}
        IFS=. read -r -a parts <<<"$a"
        for o in "${parts[@]}"; do
            [ "$((10#$o))" -le 255 ] || return 1
        done
        [[ $v != */* ]] || [ "${v#*/}" -le 32 ]
        return
    fi
    [[ $v =~ $ipv6 && $v == *:* ]] || return 1
    [[ $v != */* ]] || [ "${v#*/}" -le 128 ]
}

if ! plan=$(plan_source 2>/dev/null); then
    echo "abuse-firewall: no plan; leaving the firewall as it is" >&2
    exit 0
fi

mode=""
allow4=() allow6=() block4=() block6=()
count=0
while read -r kind a b extra; do
    [ -n "$kind" ] || continue
    if [ -n "${extra:-}" ]; then
        echo "abuse-firewall: unexpected line; leaving the firewall as it is" >&2
        report "${mode:-unknown}" 0 0 "the plan had an unexpected line"
        exit 1
    fi
    case $kind in
    mode)
        case $a in off | log | apply) mode=$a ;; *)
            echo "abuse-firewall: unknown mode" >&2
            exit 1
            ;;
        esac
        ;;
    allow)
        valid_ip "$a" || { echo "abuse-firewall: bad allow entry" >&2; exit 1; }
        if [[ $a == *:* ]]; then allow6+=("$a"); else allow4+=("$a"); fi
        ;;
    block)
        valid_ip "$a" || { echo "abuse-firewall: bad block entry" >&2; exit 1; }
        [[ $b =~ ^[0-9]{1,7}$ ]] && [ "$b" -ge 1 ] || { echo "abuse-firewall: bad timeout" >&2; exit 1; }
        count=$((count + 1))
        if [[ $a == *:* ]]; then block6+=("$a timeout ${b}s"); else block4+=("$a timeout ${b}s"); fi
        ;;
    *)
        echo "abuse-firewall: unexpected line; leaving the firewall as it is" >&2
        report "${mode:-unknown}" 0 0 "the plan had an unexpected line"
        exit 1
        ;;
    esac
done <<<"$plan"

[ -n "$mode" ] || { echo "abuse-firewall: the plan has no mode" >&2; exit 1; }
if [ "$count" -gt "$max_entries" ]; then
    report "$mode" "$count" 0 "more than $max_entries entries"
    exit 1
fi

join() {
    local first=1 item
    for item in "$@"; do
        if [ "$first" = 1 ]; then first=0; else printf ', '; fi
        printf '%s' "$item"
    done
}

render() {
    local dev=$1
    if ! nft list table inet "$table" >/dev/null 2>&1; then
        cat <<NFT
table inet $table {
    set block4 { type ipv4_addr; flags interval, timeout; }
    set block6 { type ipv6_addr; flags interval, timeout; }
    set allow4 { type ipv4_addr; flags interval; }
    set allow6 { type ipv6_addr; flags interval; }
    set client_ports { type inet_service; elements = { $ports } }
    chain forward {
        type filter hook forward priority filter - 20; policy accept;
        iifname "$dev" ip saddr @allow4 accept
        iifname "$dev" ip6 saddr @allow6 accept
        iifname "$dev" ct status dnat ct original proto-dst @client_ports ip saddr @block4 counter drop
        iifname "$dev" ct status dnat ct original proto-dst @client_ports ip6 saddr @block6 counter drop
    }
}
NFT
    fi
    printf 'flush set inet %s block4\nflush set inet %s block6\nflush set inet %s allow4\nflush set inet %s allow6\n' "$table" "$table" "$table" "$table"
    [ "${#allow4[@]}" = 0 ] || printf 'add element inet %s allow4 { %s }\n' "$table" "$(join "${allow4[@]}")"
    [ "${#allow6[@]}" = 0 ] || printf 'add element inet %s allow6 { %s }\n' "$table" "$(join "${allow6[@]}")"
    [ "${#block4[@]}" = 0 ] || printf 'add element inet %s block4 { %s }\n' "$table" "$(join "${block4[@]}")"
    [ "${#block6[@]}" = 0 ] || printf 'add element inet %s block6 { %s }\n' "$table" "$(join "${block6[@]}")"
}

dropped() {
    nft list chain inet "$table" forward 2>/dev/null | grep -o 'packets [0-9]*' | awk '{n += $2} END {print n + 0}'
}

if [ "$mode" != apply ]; then
    nft delete table inet "$table" 2>/dev/null || true
    report "$mode" "$count" 0
    exit 0
fi

dev=$(ip -o route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}')
[ -n "$dev" ] || { report "$mode" "$count" 0 "no route to find the public interface"; exit 1; }
# One nft -f is one transaction: on any error the old contents stay.
if ! error=$(render "$dev" | nft -f - 2>&1); then
    echo "abuse-firewall: nft refused the update: $error" >&2
    report "$mode" "$count" "$(dropped)" "nft refused the update"
    exit 1
fi
report "$mode" "$count" "$(dropped)"
