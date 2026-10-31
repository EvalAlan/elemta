#!/bin/bash
# Apply the protected bootstrap credential to an existing directory. Local
# socket authentication keeps both the old and new password out of argv and
# allows repair even when the directory predates generated credentials.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$root/scripts/dev-secrets.sh" >/dev/null
# shellcheck disable=SC1091
. "${ELEMTA_SECRETS_DIR:-$root/deployments/compose/.secrets}/ldap-admin.env"
: "${LDAP_ADMIN_PASSWORD:?missing protected LDAP admin credential}"
# shellcheck source=SCRIPTDIR/lib/ldap.sh
. "$root/scripts/lib/ldap.sh"
# The administrator password is configuration, so every node gets it. (In a
# replicated directory the nodes also replicate as the administrator, with
# the password they were started with: restart them after changing it.)
for node in $(ldap_nodes); do
    hash=$(printf '%s' "$LDAP_ADMIN_PASSWORD" | ldap_exec "$node" slappasswd -T /dev/stdin)
    printf 'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcRootPW\nolcRootPW: %s\n' "$hash" |
        ldap_exec "$node" ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null
    printf '%s' "$LDAP_ADMIN_PASSWORD" |
        ldap_exec "$node" ldapwhoami -x -H ldapi:/// -D cn=admin,dc=example,dc=com -y /dev/stdin >/dev/null
done
echo 'LDAP bootstrap credential applied and verified.'
