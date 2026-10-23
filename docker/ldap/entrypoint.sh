#!/bin/sh
# Starts the directory, creating it on first start.
#
#   elemta-ldap serve   create the directory if it has no configuration yet,
#                       then run slapd in the foreground (the default)
#   elemta-ldap init    create it and exit (restore and the restore drill)
#
# A new directory gets the configuration in slapd.ldif.in and then either the
# entries in $LDAP_IMPORT (a slapcat export: a backup, or the previous
# image's directory moved by scripts/ldap-migrate.sh) or just the base entry.
# Creating it is the only time the configuration is written here; after that
# it is cn=config's to change, over ldapi:///, except replication below.
#
# Replication (multi-provider: every node takes writes and passes them to
# the others). Every node gets the same LDAP_REPLICATION_PEERS, the URLs of
# all nodes in order, and its own position in that list as LDAP_SERVER_ID
# (1, 2, ...). In a Kubernetes StatefulSet the ID defaults to the pod's
# ordinal plus one. At each start, before slapd runs, the node's own
# configuration is brought in line: a server ID, the sync provider, one
# replication agreement per other node, multi-provider on. Without peers it
# is a single directory as before. Configuration (schema, access rules) is
# not replicated; the scripts that change it apply it to every node.
#
# A node created with peers starts empty and fetches everything from them,
# except node 1, which creates a new directory as a single node does; a
# node 1 rebuilt into an existing cluster sets LDAP_JOIN=1 to fetch instead.
set -eu

conf=${LDAP_CONFIG_DIR:-/etc/ldap/slapd.d}
data=${LDAP_DATA_DIR:-/var/lib/ldap}
base=${LDAP_BASE_DN:-dc=example,dc=com}
org=${LDAP_ORGANISATION:-Example Corp}
import=${LDAP_IMPORT:-/import/data.ldif}
peers=$(echo "${LDAP_REPLICATION_PEERS:-}" | tr ',' ' ')
server_id=${LDAP_SERVER_ID:-}
if [ -n "$peers" ] && [ -z "$server_id" ]; then
    host=$(hostname)
    ordinal=${host##*-}
    case $ordinal in '' | *[!0-9]*) echo "elemta-ldap: set LDAP_SERVER_ID (this node's place in LDAP_REPLICATION_PEERS)" >&2 && exit 1 ;; esac
    server_id=$((ordinal + 1))
fi
join=${LDAP_JOIN:-}
if [ -z "$join" ] && [ -n "$peers" ] && [ "$server_id" != 1 ]; then
    join=1
fi

init() {
    [ -e "$conf/cn=config.ldif" ] && return 0
    # The compose stack mounts the previous image's database at /legacy. If it
    # holds a directory and nothing was handed over, starting empty would
    # lock every account out; stop and say how to move it instead.
    if [ ! -f "$import" ] && [ -f /legacy/data.mdb ]; then
        echo "elemta-ldap: the previous directory image's data is still here and has not been moved." >&2
        echo "elemta-ldap: run scripts/ldap-migrate.sh; it exports it and starts this one with it." >&2
        exit 1
    fi
    if [ -n "$(ls -A "$data" 2>/dev/null)" ]; then
        echo "elemta-ldap: $data holds a database but $conf has no configuration; not overwriting it." >&2
        exit 1
    fi
    : "${LDAP_ADMIN_PASSWORD:?elemta-ldap: LDAP_ADMIN_PASSWORD is needed to create the directory}"
    mkdir -p "$conf" "$data"
    hash=$(printf '%s' "$LDAP_ADMIN_PASSWORD" | slappasswd -o module-path=/usr/lib/openldap -o module-load=pw-sha2 -h '{SSHA512}' -T /dev/stdin)
    rendered=$(mktemp)
    sed -e "s|@BASE@|$base|g" -e "s|@DATA@|$data|g" -e "s|@ROOTPW@|$hash|" /usr/share/elemta-ldap/slapd.ldif.in >"$rendered"
    # Not -q here: quick mode skips the schema parsing cn=config needs and
    # rejects the standard schema files.
    slapadd -n 0 -F "$conf" -l "$rendered"
    rm -f "$rendered"
    if [ "$join" = 1 ]; then
        echo "elemta-ldap: created an empty replica; its entries come from $peers"
    elif [ -f "$import" ]; then
        slapadd -q -n 1 -F "$conf" -l "$import"
        echo "elemta-ldap: created the directory from $import ($(grep -c '^dn:' "$import") entries)"
    else
        dc=${base#dc=}
        dc=${dc%%,*}
        printf 'dn: %s\nobjectClass: top\nobjectClass: dcObject\nobjectClass: organization\no: %s\ndc: %s\n' "$base" "$org" "$dc" |
            slapadd -q -n 1 -F "$conf"
        echo "elemta-ldap: created an empty directory for $base"
    fi
    chown -R ldap:ldap "$conf" "$data"
}

# config_has <filter> <text>: the configuration has an entry matching
# filter whose LDIF contains text.
config_has() {
    slapcat -n 0 -F "$conf" -a "$1" -o ldif_wrap=no 2>/dev/null | grep -qF "$2"
}

# replicate brings this node's replication settings in line with the
# environment, offline, before slapd starts.
replicate() {
    [ -e "$conf/cn=config.ldif" ] || return 0
    db="olcDatabase={1}mdb,cn=config"
    if [ -z "$peers" ]; then
        if config_has '(olcSyncrepl=*)' 'olcSyncrepl'; then
            printf 'dn: %s\nchangetype: modify\ndelete: olcSyncrepl\n-\nreplace: olcMultiProvider\nolcMultiProvider: FALSE\n' "$db" | slapmodify -n 0 -F "$conf" >/dev/null
            # Rewritten as root; slapd reads it as ldap.
            chown -R ldap:ldap "$conf"
            echo "elemta-ldap: replication off"
        fi
        return 0
    fi
    : "${LDAP_ADMIN_PASSWORD:?elemta-ldap: LDAP_ADMIN_PASSWORD is needed for replication}"
    changes=$(mktemp)
    if ! config_has '(objectClass=olcModuleList)' 'syncprov'; then
        printf 'dn: cn=module{0},cn=config\nchangetype: modify\nadd: olcModuleLoad\nolcModuleLoad: syncprov\n\n' >>"$changes"
    fi
    printf 'dn: cn=config\nchangetype: modify\nreplace: olcServerID\nolcServerID: %s\n\n' "$server_id" >>"$changes"
    for index in "entryCSN eq" "entryUUID eq"; do
        config_has '(olcDatabase={1}mdb)' "olcDbIndex: $index" ||
            printf 'dn: %s\nchangetype: modify\nadd: olcDbIndex\nolcDbIndex: %s\n\n' "$db" "$index" >>"$changes"
    done
    # The agreement binds as the directory administrator, whose password
    # every node has. Its syntax can't carry a quote or backslash in the
    # password (the generated ones are letters and digits).
    # shellcheck disable=SC1003 # a literal backslash, not an escape
    case $LDAP_ADMIN_PASSWORD in *'"'* | *'\'*)
        echo 'elemta-ldap: replication needs an LDAP_ADMIN_PASSWORD without " or \' >&2
        exit 1
        ;;
    esac
    secret=$LDAP_ADMIN_PASSWORD
    {
        printf 'dn: %s\nchangetype: modify\nreplace: olcSyncrepl\n' "$db"
        i=0
        for url in $peers; do
            i=$((i + 1))
            [ "$i" = "$server_id" ] && continue
            printf 'olcSyncrepl: rid=%03d provider=%s bindmethod=simple binddn="cn=admin,%s" credentials="%s" searchbase="%s" type=refreshAndPersist retry="5 5 60 +" timeout=5 network-timeout=5\n' "$i" "$url" "$base" "$secret" "$base"
        done
        printf -- '-\nreplace: olcMultiProvider\nolcMultiProvider: TRUE\n\n'
    } >>"$changes"
    slapmodify -n 0 -F "$conf" -l "$changes" >/dev/null
    rm -f "$changes"
    if ! config_has '(objectClass=olcSyncProvConfig)' 'syncprov'; then
        # The provider side, so the other nodes can sync from this one.
        printf 'dn: olcOverlay=syncprov,%s\nobjectClass: olcOverlayConfig\nobjectClass: olcSyncProvConfig\nolcOverlay: syncprov\nolcSpCheckpoint: 100 10\nolcSpSessionLog: 1000\n' "$db" |
            slapadd -n 0 -F "$conf" >/dev/null
    fi
    chown -R ldap:ldap "$conf"
    echo "elemta-ldap: replicating as node $server_id of $(echo "$peers" | wc -w)"
}

case "${1:-serve}" in
serve)
    init
    replicate
    mkdir -p /var/lib/openldap/run
    chown ldap:ldap /var/lib/openldap/run
    # slapd sizes its connection table to the open-file limit. Docker gives
    # containers about a million; containerd as k3s runs it gives ~a billion,
    # and slapd is killed for memory before it starts. A directory needs a
    # few thousand connections at most.
    if [ "$(ulimit -n)" = unlimited ] || [ "$(ulimit -n)" -gt 65536 ]; then
        ulimit -n 65536
    fi
    # -d keeps slapd in the foreground for the container; 0 logs nothing
    # beyond start-up failures, as before. LDAP_DEBUG=256 logs every operation.
    exec slapd -d "${LDAP_DEBUG:-0}" -u ldap -g ldap -F "$conf" -h "ldap:/// ldapi:///"
    ;;
init)
    init
    ;;
*)
    exec "$@"
    ;;
esac
