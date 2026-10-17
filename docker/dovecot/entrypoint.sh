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
