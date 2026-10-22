#!/bin/bash
# Brings an existing directory up to the current mail schema and layout.
# Safe to run repeatedly; scripts/cloud-deploy.sh, ldap-migrate.sh and the
# dev bootstrap run it on every deploy.
#
#   - adds the attribute types and object classes of
#     docker/ldap/10-mail-schema.ldif that the directory lacks, by name;
#     a definition already there is never changed
#   - keeps memberOf for groupOfNames (member DNs), the group style Elemta
#     and directory lists use, and indexes what lookups search on
#   - moves accounts from extensibleObject, which switches schema checking
#     off for the entry, to elemtaMailAccount
#   - creates the branches mail entries live in and removes the unused,
#     empty ou=mailgroups
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
schema="$root/docker/ldap/10-mail-schema.ldif"
if [ "${ELEMTA_STACK:-}" = k8s ]; then
    EXEC=(kubectl -n "${K8S_NAMESPACE:-elemta}" exec -i deploy/elemta-ldap --)
else
    EXEC=(docker exec -i elemta-ldap)
fi
BASE="dc=example,dc=com"
ROOT=(-Q -Y EXTERNAL -H ldapi:///)
search() { "${EXEC[@]}" ldapsearch -LLL -o ldif-wrap=no "${ROOT[@]}" "$@" 2>/dev/null; }
modify() { "${EXEC[@]}" ldapmodify "${ROOT[@]}" >/dev/null; }

# --- schema ---------------------------------------------------------------
dn=$(search -b cn=schema,cn=config '(cn=*elemta-mail)' dn | sed -n 's/^dn: //p')
if [ -z "$dn" ]; then
    "${EXEC[@]}" ldapadd "${ROOT[@]}" <"$schema" >/dev/null
    echo "ldap-schema: installed the mail schema"
else
    have=$(search -b "$dn" -s base olcAttributeTypes olcObjectClasses)
    added=0
    # Attribute types first: a new class may name a new attribute.
    for kind in olcAttributeTypes olcObjectClasses; do
        while IFS= read -r line; do
            name=$(sed -n "s/.* NAME '\([^']*\)'.*/\1/p" <<<"$line")
            grep -q "NAME '$name'" <<<"$have" && continue
            printf 'dn: %s\nchangetype: modify\nadd: %s\n%s\n' "$dn" "$kind" "$line" | modify
            added=$((added + 1))
        done < <(grep "^$kind: " "$schema")
    done
    echo "ldap-schema: mail schema up to date ($added definitions added)"
fi

# --- groups and indexes ---------------------------------------------------
db="olcDatabase={1}mdb,cn=config"
overlay=$(search -b "$db" '(objectClass=olcMemberOf)' dn | sed -n 's/^dn: //p')
if [ -n "$overlay" ] && ! search -b "$overlay" -s base olcMemberOfGroupOC | grep -q '^olcMemberOfGroupOC: groupOfNames$'; then
    printf 'dn: %s\nchangetype: modify\nreplace: olcMemberOfGroupOC\nolcMemberOfGroupOC: groupOfNames\n-\nreplace: olcMemberOfMemberAD\nolcMemberOfMemberAD: member\n' "$overlay" | modify
    echo "ldap-schema: memberOf now follows groupOfNames"
fi
indexes=$(search -b "$db" -s base olcDbIndex)
for index in "member eq" "elemtaDomainName eq"; do
    grep -qx "olcDbIndex: $index" <<<"$indexes" && continue
    printf 'dn: %s\nchangetype: modify\nadd: olcDbIndex\nolcDbIndex: %s\n' "$db" "$index" | modify
done

# --- branches ---------------------------------------------------------------
for ou in people groups domains mail-addresses; do
    search -b "ou=$ou,$BASE" -s base dn | grep -q '^dn:' && continue
    printf 'dn: ou=%s,%s\nobjectClass: organizationalUnit\nou: %s\n' "$ou" "$BASE" "$ou" |
        "${EXEC[@]}" ldapadd "${ROOT[@]}" >/dev/null
done
if search -b "ou=mailgroups,$BASE" -s base dn | grep -q '^dn:' &&
    [ "$(search -b "ou=mailgroups,$BASE" -s one dn | grep -c '^dn:')" = 0 ]; then
    "${EXEC[@]}" ldapdelete "${ROOT[@]}" "ou=mailgroups,$BASE"
    echo "ldap-schema: removed the empty ou=mailgroups"
fi

# --- accounts ---------------------------------------------------------------
moved=0
failed=0
while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    if printf 'dn: %s\nchangetype: modify\nadd: objectClass\nobjectClass: elemtaMailAccount\n-\ndelete: objectClass\nobjectClass: extensibleObject\n' "$entry" | modify 2>/dev/null; then
        moved=$((moved + 1))
    else
        # An attribute that only extensibleObject allowed: left as it is,
        # and named so someone can look.
        echo "ldap-schema: left $entry on extensibleObject (it has attributes the account class doesn't allow)" >&2
        failed=$((failed + 1))
    fi
done < <(search -b "ou=people,$BASE" '(objectClass=extensibleObject)' dn | sed -n 's/^dn: //p')
[ "$moved" = 0 ] && [ "$failed" = 0 ] || echo "ldap-schema: $moved accounts moved to elemtaMailAccount, $failed left"
