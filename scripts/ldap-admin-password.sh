#!/bin/bash
# Apply the protected bootstrap credential to an existing directory. Local
# socket authentication keeps both the old and new password out of argv and
# allows repair even when the directory predates generated credentials.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$root/scripts/dev-secrets.sh" >/dev/null
# shellcheck disable=SC1091
. "$root/deployments/compose/.secrets/ldap-admin.env"
: "${LDAP_ADMIN_PASSWORD:?missing protected LDAP admin credential}"
if [ "${ELEMTA_STACK:-}" = k8s ]; then
    EXEC=(kubectl -n "${K8S_NAMESPACE:-elemta}" exec -i deploy/elemta-ldap --)
else
    EXEC=(docker exec -i elemta-ldap)
fi
hash=$(printf '%s' "$LDAP_ADMIN_PASSWORD" | "${EXEC[@]}" slappasswd -T /dev/stdin)
printf 'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcRootPW\nolcRootPW: %s\n' "$hash" |
    "${EXEC[@]}" ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null
printf '%s' "$LDAP_ADMIN_PASSWORD" |
    "${EXEC[@]}" ldapwhoami -x -H ldapi:/// -D cn=admin,dc=example,dc=com -y /dev/stdin >/dev/null
echo 'LDAP bootstrap credential applied and verified.'
