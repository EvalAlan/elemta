#!/bin/bash
# Initialize LDAP users if they don't exist
# Run by the install-dev targets to make sure the users are loaded

set -e

# The Compose dev stack by default; ELEMTA_STACK=k8s (set by the k8s-* make
# targets) runs the same commands in the Kubernetes one.
# Data goes to the directory's first node; a replicated directory passes it
# to the others (scripts/lib/ldap.sh).
# shellcheck source=SCRIPTDIR/lib/ldap.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/ldap.sh"
node=$(ldap_first)
LDAP_EXEC=(ldap_exec "$node")
if [ "${ELEMTA_STACK:-}" = "k8s" ]; then
    LDAP_LOGS="kubectl -n ${K8S_NAMESPACE:-elemta} logs $node"
else
    LDAP_LOGS="docker logs $node"
fi

echo "🔍 Checking if LDAP users need initialization..."

# Wait for LDAP to be healthy
timeout=60
counter=0
while ! "${LDAP_EXEC[@]}" ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b "dc=example,dc=com" -s base > /dev/null 2>&1; do
    sleep 2
    counter=$((counter + 2))
    if [ $counter -ge $timeout ]; then
        echo "❌ LDAP failed to become healthy"
        exit 1
    fi
done

# The mail schema and branches, current whatever the directory was created
# with. Idempotent.
"$(dirname "${BASH_SOURCE[0]}")/ldap-schema.sh"

# Every service binds as its own least-privilege account; create them (and
# the access rules) before anything needs them. Idempotent.
"$(dirname "${BASH_SOURCE[0]}")/ldap-admin-password.sh"
"$(dirname "${BASH_SOURCE[0]}")/ldap-service-accounts.sh"

# Whether the users are already there.
#
# This and the verification below used to combine -x (simple authentication)
# with -Y EXTERNAL (SASL). ldapsearch refuses that outright, so the check failed
# every time: the script decided on every run that the users were missing,
# re-added them, and ldapadd then failed with "Already exists" — which under
# `set -e` ended the script before it could verify anything. The warning about
# verification being "unclear" was this, not a problem with LDAP.
ldap_has_users() {
    "${LDAP_EXEC[@]}" ldapsearch -Q -Y EXTERNAL -H ldapi:/// \
        -b "ou=people,dc=example,dc=com" "(uid=user)" 2>/dev/null | grep -q "^dn: uid=user"
}

if ldap_has_users; then
    echo "✅ LDAP users already initialized"
    exit 0
fi

echo "📝 LDAP users not found, adding them now..."

# Adding entries that already exist is not a failure for an idempotent
# initialiser, so this must not take `set -e` with it.
# -c: entries the steps above already made (branches) are skipped, not
# the end of the file.
"${LDAP_EXEC[@]}" ldapadd -c -Q -Y EXTERNAL -H ldapi:/// \
    -f /docker-entrypoint-initdb.d/99-stress-users.ldif 2>&1 | grep -v "Already exists" || true

sleep 2

if ldap_has_users; then
    echo "✅ LDAP users initialized successfully"
    exit 0
else
    echo "⚠️  LDAP users could not be verified — check: $LDAP_LOGS"
    exit 0
fi
