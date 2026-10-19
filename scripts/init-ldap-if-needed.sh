#!/bin/bash
# Initialize LDAP users if they don't exist
# Run by the install-dev targets to make sure the users are loaded

set -e

# The Compose dev stack by default; ELEMTA_STACK=k8s (set by the k8s-* make
# targets) runs the same commands in the Kubernetes one.
if [ "${ELEMTA_STACK:-}" = "k8s" ]; then
    LDAP_EXEC=(kubectl -n "${K8S_NAMESPACE:-elemta}" exec deploy/elemta-ldap --)
    LDAP_SCHEMA_EXEC=(kubectl -n "${K8S_NAMESPACE:-elemta}" exec -i deploy/elemta-ldap --)
    LDAP_LOGS="kubectl -n ${K8S_NAMESPACE:-elemta} logs deploy/elemta-ldap"
else
    LDAP_EXEC=(docker exec elemta-ldap)
    LDAP_SCHEMA_EXEC=(docker exec -i elemta-ldap)
    LDAP_LOGS="docker logs elemta-ldap"
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

# Mail administration uses standard mail aliases, status and quota attributes.
# Existing full mail schemas already define them; never register duplicate OIDs.
if ! "${LDAP_EXEC[@]}" ldapsearch -LLL -o ldif-wrap=no -Y EXTERNAL -H ldapi:/// \
    -b cn=schema,cn=config '(objectClass=olcSchemaConfig)' olcAttributeTypes 2>/dev/null | grep -q "NAME 'mailAlternateAddress'"; then
    # Stream the shipped schema so this works on both compose mounts and
    # Kubernetes deployments whose existing ConfigMap predates this file.
    "${LDAP_SCHEMA_EXEC[@]}" ldapadd -Y EXTERNAL -H ldapi:/// \
        < "$(dirname "${BASH_SOURCE[0]}")/../docker/ldap/10-mail-schema.ldif"
fi

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
"${LDAP_EXEC[@]}" ldapadd -Q -Y EXTERNAL -H ldapi:/// \
    -f /docker-entrypoint-initdb.d/99-stress-users.ldif 2>&1 | grep -v "Already exists" || true

sleep 2

if ldap_has_users; then
    echo "✅ LDAP users initialized successfully"
    exit 0
else
    echo "⚠️  LDAP users could not be verified — check: $LDAP_LOGS"
    exit 0
fi
