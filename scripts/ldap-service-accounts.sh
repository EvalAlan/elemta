#!/bin/bash
# Creates the dev directory's service accounts and the access rules that
# confine each one to what its component needs. Safe to run repeatedly:
# existing accounts get their passwords re-synced from the secrets file and
# the rules are replaced as a whole.
#
#   cn=elemta-smtp    Elemta's SMTP AUTH and recipient lookups: read mailbox
#                     entries, address claims and groups.
#   cn=webmail        Webmail lookups (finding a user's entry to change their
#                     own password): read mailbox entries.
#   cn=webmail-reset  Forgot-password and administrator resets: read mailbox
#                     entries, write their passwords. Nothing else.
#   cn=provisioner    Mail administration (console and `elemta provision`):
#                     create, change and delete mailbox entries, address
#                     claims, lists and domains. No access to service
#                     accounts or other trees.
#   cn=mailbox        The mailbox service: read mailbox entries (delivery and
#                     sign-in lookups, forwarding, send-as), lists and domains.
#
# Users may change their own forwarding (the webmail does it as them);
# nothing else in their entry. No account can read a password. cn=admin remains the directory's root for
# bootstrap only; no running service binds as it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$root/scripts/dev-secrets.sh" >/dev/null
# shellcheck disable=SC1091
. "${ELEMTA_SECRETS_DIR:-$root/deployments/compose/.secrets}/ldap-services.env"

# shellcheck source=SCRIPTDIR/lib/ldap.sh
. "$root/scripts/lib/ldap.sh"
# Accounts are data, written once and replicated; the access rules are each
# node's configuration, applied to all of them below.
EXEC=(ldap_exec "$(ldap_first)")
BASE="dc=example,dc=com"
SVC="ou=services,$BASE"
ADMIN=(-Q -Y EXTERNAL -H ldapi:///)

# Creating this container requires write access to the directory root. Keep
# that privilege in bootstrap rather than granting it to the provisioner.
if ! "${EXEC[@]}" ldapsearch "${ADMIN[@]}" -b "ou=mail-addresses,$BASE" -s base dn >/dev/null 2>&1; then
    printf 'dn: ou=mail-addresses,%s\nobjectClass: organizationalUnit\nou: mail-addresses\n' "$BASE" |
        "${EXEC[@]}" ldapadd "${ADMIN[@]}" >/dev/null
fi

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
account elemta-smtp "$LDAP_SMTP_PASSWORD" "Elemta SMTP authentication and recipient lookups"
account webmail "$LDAP_WEBMAIL_PASSWORD" "Webmail user lookups"
account mailbox "$LDAP_MAILBOX_PASSWORD" "Mailbox identity and delivery lookups"
account webmail-reset "$LDAP_WEBMAIL_RESET_PASSWORD" "Webmail password resets"
account provisioner "$LDAP_PROVISIONER_PASSWORD" "Mail administration"

d() { echo "dn.exact=\"cn=$1,$SVC\""; }
# Order matters: OpenLDAP uses the first rule whose target matches. Rule 0,
# root over the local socket, is the image's own and is kept.
rules=$(cat <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
olcAccess: {1}to dn.subtree="ou=people,$BASE" attrs=userPassword,shadowLastChange by self write by $(d webmail-reset) write by $(d provisioner) write by anonymous auth by * none
olcAccess: {2}to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none
olcAccess: {3}to dn.subtree="ou=people,$BASE" attrs=elemtaForwardTo,elemtaForwardKeepCopy by self write by $(d provisioner) write by $(d elemta-smtp) read by $(d webmail) read by $(d mailbox) read by * none
olcAccess: {4}to dn.subtree="ou=people,$BASE" by $(d provisioner) write by $(d elemta-smtp) read by $(d webmail) read by $(d mailbox) read by $(d webmail-reset) read by self read by * none
olcAccess: {5}to dn.subtree="ou=mail-addresses,$BASE" by $(d provisioner) write by $(d elemta-smtp) read by * none
olcAccess: {6}to dn.subtree="ou=groups,$BASE" by $(d provisioner) write by $(d elemta-smtp) read by $(d mailbox) read by * none
olcAccess: {7}to dn.subtree="ou=domains,$BASE" by $(d provisioner) write by $(d elemta-smtp) read by $(d mailbox) read by * none
olcAccess: {8}to dn.base="$BASE" by users read by * none
olcAccess: {9}to * by self read by * none
LDIF
)
for node in $(ldap_nodes); do
    printf '%s\n' "$rules" | ldap_exec "$node" ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1
done
echo "✅ LDAP service accounts and access rules in place"
