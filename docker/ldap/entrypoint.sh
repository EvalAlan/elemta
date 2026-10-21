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
# it is cn=config's to change, over ldapi:///.
set -eu

conf=${LDAP_CONFIG_DIR:-/etc/ldap/slapd.d}
data=${LDAP_DATA_DIR:-/var/lib/ldap}
base=${LDAP_BASE_DN:-dc=example,dc=com}
org=${LDAP_ORGANISATION:-Example Corp}
import=${LDAP_IMPORT:-/import/data.ldif}

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
    if [ -f "$import" ]; then
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
