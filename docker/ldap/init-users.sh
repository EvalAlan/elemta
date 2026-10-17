#!/bin/bash
# Initialize LDAP users on first startup

set -e

if ! ldapsearch -LLL -o ldif-wrap=no -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config '(objectClass=olcSchemaConfig)' olcAttributeTypes 2>/dev/null | grep -q "NAME 'mailAlternateAddress'"; then
    ldapadd -Y EXTERNAL -H ldapi:/// -f /docker-entrypoint-initdb.d/10-mail-schema.ldif
fi

# Only run if users don't exist yet
if ldapsearch -x -H ldap://localhost -b "ou=people,dc=example,dc=com" "(uid=demo)" | grep -q "uid: demo"; then
    echo "Users already exist, skipping initialization"
    exit 0
fi

echo "Initializing LDAP users from 99-stress-users.ldif..."

# Load bootstrap file
ldapadd -x -D "cn=admin,dc=example,dc=com" -w "$LDAP_ADMIN_PASSWORD" -f /docker-entrypoint-initdb.d/99-stress-users.ldif || true

echo "LDAP users initialized"

