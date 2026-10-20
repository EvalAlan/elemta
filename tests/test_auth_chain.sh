#!/bin/bash

echo "=== Testing Authentication Chain ==="

echo "1. Testing LDAP user lookup..."
docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=people,dc=example,dc=com" "(mail=recipient@example.com)" mail userPassword

echo -e "\n2. Testing LDAP bind authentication..."
docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "uid=recipient,ou=people,dc=example,dc=com" -w password -b "ou=people,dc=example,dc=com" "(mail=recipient@example.com)" mail

echo -e "\n3. Testing elemta-mailbox LDAP config..."
docker exec elemta-mailbox cat /etc/elemta/mailbox.toml | grep -A 20 "\[ldap\]"

echo -e "\n4. Testing direct IMAP authentication (STARTTLS)..."
echo -e "a001 LOGIN recipient@example.com password\na002 LOGOUT" | docker exec -i elemta-mailbox nc localhost 11143

echo -e "\nAuthentication chain test completed."