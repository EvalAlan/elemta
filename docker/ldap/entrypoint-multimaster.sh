#!/bin/sh
# Multi-master LDAP entrypoint.
# Starts the directory with N-way multi-master replication.
#
#   elemta-ldap-mm serve   create the directory if it has no configuration yet,
#                          then run slapd in the foreground (the default)
#   elemta-ldap-mm init    create it and exit (restore and the restore drill)
#
# Environment variables:
#   LDAP_SERVER_ID         Unique server ID (1, 2, 3...) - REQUIRED
#   LDAP_PEER_URLS         Comma-separated peer LDAP URLs (ldap://host:389) - REQUIRED for multi-master
#   LDAP_BASE_DN           Base DN (default: dc=example,dc=com)
#   LDAP_ORGANISATION      Organisation name (default: Example Corp)
#   LDAP_ADMIN_PASSWORD    Admin password - REQUIRED
#   LDAP_CONFIG_DIR        Config directory (default: /etc/ldap/slapd.d)
#   LDAP_DATA_DIR          Data directory (default: /var/lib/ldap)
#   LDAP_IMPORT            Import LDIF file (default: /import/data.ldif)
set -eu

conf=${LDAP_CONFIG_DIR:-/etc/ldap/slapd.d}
data=${LDAP_DATA_DIR:-/var/lib/ldap}
base=${LDAP_BASE_DN:-dc=example,dc=com}
org=${LDAP_ORGANISATION:-Example Corp}
import=${LDAP_IMPORT:-/import/data.ldif}
server_id=${LDAP_SERVER_ID:-}
peer_urls=${LDAP_PEER_URLS:-}

# Validate required multi-master parameters
if [ -z "$server_id" ]; then
    echo "elemta-ldap-mm: LDAP_SERVER_ID is required for multi-master (1, 2, 3...)" >&2
    exit 1
fi
if [ -z "$peer_urls" ]; then
    echo "elemta-ldap-mm: LDAP_PEER_URLS is required for multi-master (comma-separated ldap:// URLs)" >&2
    exit 1
fi

init() {
    [ -e "$conf/cn=config.ldif" ] && return 0

    # The compose stack mounts the previous image's database at /legacy. If it
    # holds a directory and nothing was handed over, starting empty would
    # lock every account out; stop and say how to move it instead.
    if [ ! -f "$import" ] && [ -f /legacy/data.mdb ]; then
        echo "elemta-ldap-mm: the previous directory image's data is still here and has not been moved." >&2
        echo "elemta-ldap-mm: run scripts/ldap-migrate.sh; it exports it and starts this one with it." >&2
        exit 1
    fi
    if [ -n "$(ls -A "$data" 2>/dev/null)" ]; then
        echo "elemta-ldap-mm: $data holds a database but $conf has no configuration; not overwriting it." >&2
        exit 1
    fi
    : "${LDAP_ADMIN_PASSWORD:?elemta-ldap-mm: LDAP_ADMIN_PASSWORD is needed to create the directory}"
    mkdir -p "$conf" "$data"
    hash=$(printf '%s' "$LDAP_ADMIN_PASSWORD" | slappasswd -o module-path=/usr/lib/openldap -o module-load=pw-sha2 -h '{SSHA512}' -T /dev/stdin)

    # Build syncrepl peer configuration as olcSyncrepl attributes (not modify operations)
    syncrepl_file=$(mktemp)
    rid=1
    IFS=','
    for peer in $peer_urls; do
        peer=$(echo "$peer" | xargs)  # trim whitespace
        if [ -n "$peer" ]; then
            # Generate olcSyncrepl attribute lines for direct inclusion in olcDatabase={1}mdb
            cat >>"$syncrepl_file" <<EOF
olcSyncrepl: {$rid}rid=$rid provider=$peer bindmethod=simple binddn="cn=admin,$base" credentials=$LDAP_ADMIN_PASSWORD searchbase="$base" type=refreshAndPersist retry="60 +" timeout=1 starttls=critical tls_reqcert=never
EOF
            rid=$((rid + 1))
        fi
    done
    unset IFS

    # Strip trailing newlines - printf strips them
    syncrepl_content=$(printf '%s' "$(cat "$syncrepl_file")")
    rm -f "$syncrepl_file"

    rendered=$(mktemp)
    # Debug: output syncrepl to stderr
    printf '%s\n' "$syncrepl_content" >&2
    # Use awk for template substitution - insert olcSyncrepl attributes at placeholder
    # Write syncrepl to temp file for awk to read (avoids -v multi-line issues)
    syncrepl_for_awk=$(mktemp)
    printf '%s\n' "$syncrepl_content" >"$syncrepl_for_awk"
    awk -v base="$base" -v data="$data" -v rootpw="$hash" -v server_id="$server_id" -v syncrepl_file="$syncrepl_for_awk" '
    BEGIN {
        # Read entire syncrepl file into variable
        while ((getline line < syncrepl_file) > 0) {
            syncrepl_content = syncrepl_content line "\n"
        }
        close(syncrepl_file)
        # Strip trailing newline
        gsub(/\n+$/, "", syncrepl_content)
    }
    {
        gsub("@@BASE@@", base)
        gsub("@@DATA@@", data)
        gsub("@@ROOTPW@@", rootpw)
        gsub("@@SERVER_ID@@", server_id)
        if ($0 == "@@SYNCREPL_PEERS@@") {
            if (syncrepl_content != "") {
                printf "%s\n", syncrepl_content
            }
        } else {
            print
        }
    }' /usr/share/elemta-ldap/slapd-multimaster.ldif.in >"$rendered"
    rm -f "$syncrepl_for_awk"

    # Debug: output rendered LDIF to stderr
    cat "$rendered" >&2

    # Not -q here: quick mode skips the schema parsing cn=config needs and
    # rejects the standard schema files.
    slapadd -n 0 -F "$conf" -l "$rendered"
    rm -f "$rendered"

    if [ -f "$import" ]; then
        slapadd -q -n 1 -F "$conf" -l "$import"
        echo "elemta-ldap-mm: created the directory from $import ($(grep -c '^dn:' "$import") entries)"
    else
        dc=${base#dc=}
        dc=${dc%%,*}
        printf 'dn: %s\nobjectClass: top\nobjectClass: dcObject\nobjectClass: organization\no: %s\ndc: %s\n' "$base" "$org" "$dc" |
            slapadd -q -n 1 -F "$conf"
        echo "elemta-ldap-mm: created an empty directory for $base"
    fi
    chown -R ldap:ldap "$conf" "$data"
}

case "${1:-serve}" in
serve)
    init
    mkdir -p /var/lib/openldap/run
    chown ldap:ldap /var/lib/openldap/run
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