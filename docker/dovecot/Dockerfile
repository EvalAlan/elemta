# Dovecot 2.4 from Debian 13: IMAP, LMTP, ManageSieve, LDAP auth and
# full-text search (fts-flatcurve, a Xapian index kept beside the mail).
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dovecot-core dovecot-imapd dovecot-lmtpd dovecot-ldap dovecot-sieve \
        dovecot-managesieved dovecot-flatcurve netcat-openbsd ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# vmail owns the mail. The UID stays 5000, which the existing mail volume
# and the LDAP userdb both use.
RUN groupadd -g 5000 vmail && \
    useradd -u 5000 -g vmail -d /var/mail -M -s /usr/sbin/nologin vmail && \
    mkdir -p /var/mail && chown vmail:vmail /var/mail && chmod 700 /var/mail

COPY conf/dovecot.conf /etc/dovecot/dovecot.conf
COPY entrypoint.sh /usr/local/bin/dovecot-entrypoint

EXPOSE 14143 2424 4190

ENTRYPOINT ["/usr/local/bin/dovecot-entrypoint"]
CMD ["dovecot", "-F"]
