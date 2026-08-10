#!/bin/bash
# Initialize LDAP users if they don't exist
# This script runs after docker-setup to ensure users are loaded

set -e

echo "🔍 Checking if LDAP users need initialization..."

# Wait for LDAP to be healthy
timeout=60
counter=0
while ! docker exec elemta-ldap ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com" -s base > /dev/null 2>&1; do
    sleep 2
    counter=$((counter + 2))
    if [ $counter -ge $timeout ]; then
        echo "❌ LDAP failed to become healthy"
        exit 1
    fi
done

# Whether the users are already there.
#
# This and the verification below used to combine -x (simple authentication)
# with -Y EXTERNAL (SASL). ldapsearch refuses that outright, so the check failed
# every time: the script decided on every run that the users were missing,
# re-added them, and ldapadd then failed with "Already exists" — which under
# `set -e` ended the script before it could verify anything. The warning about
# verification being "unclear" was this, not a problem with LDAP.
ldap_has_users() {
    docker exec elemta-ldap ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin \
        -b "ou=people,dc=example,dc=com" "(uid=user)" 2>/dev/null | grep -q "^dn: uid=user"
}

if ldap_has_users; then
    echo "✅ LDAP users already initialized"
    exit 0
fi

echo "📝 LDAP users not found, adding them now..."

# Adding entries that already exist is not a failure for an idempotent
# initialiser, so this must not take `set -e` with it.
docker exec elemta-ldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin \
    -f /docker-entrypoint-initdb.d/99-stress-users.ldif 2>&1 | grep -v "Already exists" || true

sleep 2

if ldap_has_users; then
    echo "✅ LDAP users initialized successfully"
    exit 0
else
    echo "⚠️  LDAP users could not be verified — check: docker logs elemta-ldap"
    exit 0
fi
