# The directory: OpenLDAP 2.6 from Alpine, configured on first start by
# entrypoint.sh. It replaces an image that was no longer maintained (OpenLDAP
# 2.4 from 2021); this one follows Alpine's security updates, and the build
# pins the base by digest so a rebuild changes only when the pin does.
#
# Paths inside the container match the previous image's (/etc/ldap/slapd.d
# for cn=config, /var/lib/ldap for the database), so the scripts that reach
# in over `docker exec` (ldapi:/// as root, slapcat, slappasswd) work as
# before. Moving an existing directory: scripts/ldap-migrate.sh.
#
# apk upgrade first: Alpine ships security fixes between base images, and
# apk add never upgrades a package the base already has. The pinned 3.24.4
# base still carried zlib 1.3.2 (CVE-2026-4738, fixed in 1.4) and OpenSSL
# 3.5.9-r0 weeks after both were fixed in the repository.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk upgrade --no-cache && apk add --no-cache \
        openldap openldap-clients openldap-back-mdb \
        openldap-overlay-memberof openldap-overlay-refint openldap-overlay-syncprov \
        openldap-passwd-sha2 openldap-passwd-argon2 \
    # The package's sample slapd.conf would win over slapd.d for tools run
    # without -F (backup.sh's slapcat); configuration lives in slapd.d only.
    && rm -f /etc/openldap/slapd.conf /etc/openldap/slapd.ldif \
    && mkdir -p /etc/ldap/slapd.d /var/lib/ldap /var/lib/openldap/run \
    && rm -rf /etc/openldap/slapd.d && ln -s /etc/ldap/slapd.d /etc/openldap/slapd.d \
    && chown ldap:ldap /etc/ldap/slapd.d /var/lib/ldap /var/lib/openldap/run

COPY docker/ldap/slapd.ldif.in docker/ldap/10-mail-schema.ldif /usr/share/elemta-ldap/
COPY docker/ldap/entrypoint.sh /usr/local/bin/elemta-ldap

EXPOSE 389
ENTRYPOINT ["/usr/local/bin/elemta-ldap"]
CMD ["serve"]
