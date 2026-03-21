#!/bin/sh
set -e

if ! getent group elemta >/dev/null 2>&1; then
  groupadd --system elemta >/dev/null 2>&1 || true
fi

if ! id elemta >/dev/null 2>&1; then
  useradd --system --gid elemta --home-dir /var/lib/elemta --shell /sbin/nologin elemta >/dev/null 2>&1 || \
  useradd --system --gid elemta --home /var/lib/elemta --shell /usr/sbin/nologin elemta >/dev/null 2>&1 || true
fi

mkdir -p /etc/elemta/conf.d \
         /etc/elemta/certs \
         /var/lib/elemta \
         /var/log/elemta \
         /var/spool/elemta/active \
         /var/spool/elemta/deferred \
         /var/spool/elemta/held \
         /var/spool/elemta/failed \
         /var/spool/elemta/quarantine \
         /var/spool/elemta/data \
         /var/spool/elemta/tmp \
         /run/elemta

chown -R elemta:elemta /var/lib/elemta /var/log/elemta /var/spool/elemta /run/elemta || true
chmod 0750 /etc/elemta || true
chmod 0600 /etc/elemta/elemta.toml || true
chmod 0700 /etc/elemta/certs || true

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
