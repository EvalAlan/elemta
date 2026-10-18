#!/bin/bash
# Creates the dev directory's service accounts and the access rules that
# confine each one to what its component needs. Safe to run repeatedly:
# existing accounts get their passwords re-synced from the secrets file and
# the rules are replaced as a whole.
#
#   cn=dovecot        Dovecot user lookups (passwords are checked by binding
#                     as the user): read mailbox entries and address claims.
#   cn=elemta-smtp    Elemta's SMTP AUTH and recipient lookups: read mailbox
#                     entries, address claims and groups.
#   cn=webmail        Webmail lookups (finding a user's entry to change their
#                     own password): read mailbox entries.
#   cn=webmail-reset  Forgot-password and administrator resets: read mailbox
#                     entries, write their passwords. Nothing else.
#   cn=provisioner    Mail administration (console and `elemta provision`):
#                     create, change and delete mailbox entries and address
#                     claims. No access to service accounts or other trees.
#
# No account can read a password. cn=admin remains the directory's root for
# bootstrap only; no running service binds as it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$root/scripts/dev-secrets.sh" >/dev/null
# shellcheck disable=SC1091
. "$root/deployments/compose/.secrets/ldap-services.env"

if [ "${ELEMTA_STACK:-}" = "k8s" ]; then
    EXEC=(kubectl -n "${K8S_NAMESPACE:-elemta}" exec -i deploy/elemta-ldap --)
else
    EXEC=(docker exec -i elemta-ldap)
fi
BASE="dc=example,dc=com"
SVC="ou=services,$BASE"
ADMIN=(-x -D "cn=admin,$BASE" -w admin)

if ! "${EXEC[@]}" ldapsearch "${ADMIN[@]}" -b "$SVC" -s base dn >/dev/null 2>&1; then
    printf 'dn: %s\nobjectClass: organizationalUnit\nou: services\ndescription: Accounts that Elemta components bind as\n' "$SVC" |
        "${EXEC[@]}" ldapadd "${ADMIN[@]}" >/dev/null
fi

account() { # cn, password, description
    local dn="cn=$1,$SVC"
    if ! "${EXEC[@]}" ldapsearch "${ADMIN[@]}" -b "$dn" -s base dn >/dev/null 2>&1; then
        # simpleSecurityObject requires a userPassword; Password Modify
        # replaces this placeholder with a properly hashed one just below.
        printf 'dn: %s\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: %s\ndescription: %s\nuserPassword: %s\n' \
            "$dn" "$1" "$3" "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)" |
            "${EXEC[@]}" ldapadd "${ADMIN[@]}" >/dev/null
    fi
    "${EXEC[@]}" ldappasswd "${ADMIN[@]}" -s "$2" "$dn" >/dev/null
}
account dovecot "$LDAP_DOVECOT_PASSWORD" "Dovecot user lookups"
account elemta-smtp "$LDAP_SMTP_PASSWORD" "Elemta SMTP authentication and recipient lookups"
account webmail "$LDAP_WEBMAIL_PASSWORD" "Webmail user lookups"
account mailbox "$LDAP_MAILBOX_PASSWORD" "Mailbox identity and delivery lookups"
account webmail-reset "$LDAP_WEBMAIL_RESET_PASSWORD" "Webmail password resets"
account provisioner "$LDAP_PROVISIONER_PASSWORD" "Mail administration"

d() { echo "dn.exact=\"cn=$1,$SVC\""; }
# Order matters: OpenLDAP uses the first rule whose target matches. Rule 0,
# root over the local socket, is the image's own and is kept.
"${EXEC[@]}" ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
olcAccess: {1}to dn.subtree="ou=people,$BASE" attrs=userPassword,shadowLastChange by self write by $(d webmail-reset) write by $(d provisioner) write by anonymous auth by * none
olcAccess: {2}to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none
olcAccess: {3}to dn.subtree="ou=people,$BASE" by $(d provisioner) write by $(d dovecot) read by $(d elemta-smtp) read by $(d webmail) read by $(d mailbox) read by $(d webmail-reset) read by self read by * none
olcAccess: {4}to dn.subtree="ou=mail-addresses,$BASE" by $(d provisioner) write by $(d dovecot) read by $(d elemta-smtp) read by * none
olcAccess: {5}to dn.subtree="ou=groups,$BASE" by $(d elemta-smtp) read by * none
olcAccess: {6}to dn.base="$BASE" by users read by * none
olcAccess: {7}to * by self read by * none
LDIF
echo "✅ LDAP service accounts and access rules in place"
