#!/bin/sh
# Prepares the mail volume, then runs Dovecot.
#
# Each user's Maildir is /var/mail/<address>; their home, where Sieve
# scripts and delivery state live, is /var/mail/home/<address>. They used
# to be the same directory, and Maildir reads dot-names there as folders, so
# state files such as .dovecot.sieve and .dovecot.lda-dupes showed up as
# folders or broke deliveries. This moves any Sieve scripts from the old
# layout once and removes the state files that are recreated on demand.
set -eu

# The LDAP lookup account. Its password arrives in the environment (one env
# file per service in the compose stack) and is written where only Dovecot
# can read it. A stack set up without the service accounts falls back to
# the directory admin, loudly, so a plain `docker compose up` still works.
umask 077
if [ -n "${LDAP_DOVECOT_PASSWORD:-}" ]; then
    printf 'ldap_auth_dn = cn=dovecot,ou=services,dc=example,dc=com\nldap_auth_dn_password = %s\n' "$LDAP_DOVECOT_PASSWORD" >/etc/dovecot/ldap-auth.conf
else
    echo "entrypoint: WARNING: LDAP_DOVECOT_PASSWORD unset; binding as the directory admin. Run 'make ensure-dev-secrets ldap-service-accounts'." >&2
    printf 'ldap_auth_dn = cn=admin,dc=example,dc=com\nldap_auth_dn_password = admin\n' >/etc/dovecot/ldap-auth.conf
fi
chown root:dovecot /etc/dovecot/ldap-auth.conf
chmod 0640 /etc/dovecot/ldap-auth.conf
umask 022
unset LDAP_DOVECOT_PASSWORD

mkdir -p /var/mail/home
chown vmail:vmail /var/mail/home
chmod 700 /var/mail/home

for maildir in /var/mail/*@*; do
    [ -d "$maildir" ] || continue
    user=${maildir#/var/mail/}
    home=/var/mail/home/$user
    if [ -d "$maildir/sieve" ] && [ ! -e "$home/sieve" ]; then
        mkdir -p "$home"
        mv "$maildir/sieve" "$home/sieve"
        # Keep whichever script was active.
        link=/var/mail/$user.sieve
        [ -L "$maildir/.dovecot.sieve" ] && link=$maildir/.dovecot.sieve
        if [ -L "$link" ]; then
            ln -sf "sieve/$(basename "$(readlink "$link")")" "$home/.dovecot.sieve"
        fi
        chown -R vmail:vmail "$home"
        chmod 700 "$home"
        echo "entrypoint: moved Sieve scripts for $user to $home"
    fi
    rm -rf "/var/mail/$user.sieve" "/var/mail/$user.svbin" \
        "$maildir/.dovecot.sieve" "$maildir/.dovecot.svbin" \
        "$maildir/.dovecot.lda-dupes" "$maildir/.dovecot.lda-dupes.locks"
done

exec "$@"
