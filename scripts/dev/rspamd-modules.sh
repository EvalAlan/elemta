#!/usr/bin/env bash
# Toggle rspamd's external detection modules on the development stack.
#
# The stack ships with rbl, surbl, asn and fuzzy_check disabled via
# docker/rspamd/override.d/, because they need outbound DNS/UDP and make
# throughput bimodal — see the comments in those files for the measurements.
# Turning them on gets closer to a production filter at a real cost:
#
#                        disabled        enabled
#   throughput           ~130 msg/s      ~55 msg/s
#   p95 latency          ~0.65 s         ~4.3 s
#
# Usage:
#   scripts/dev/rspamd-modules.sh on     # enable detection (unmount overrides)
#   scripts/dev/rspamd-modules.sh off    # restore the fast, offline default
#   scripts/dev/rspamd-modules.sh status
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="$REPO/deployments/compose/docker-compose.yml"
MODULES=(rbl surbl asn fuzzy_check)
MARKER="# LOCAL: detection module enabled for spam-rejection testing (unmount to re-disable)"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

status() {
  local enabled=0
  for m in "${MODULES[@]}"; do
    if grep -q "^      - .*override.d/${m}\.conf" "$COMPOSE"; then
      echo "  ${m}: disabled (override mounted)"
    else
      echo "  ${m}: ENABLED"
      enabled=$((enabled + 1))
    fi
  done
  echo
  if [ "$enabled" -eq "${#MODULES[@]}" ]; then
    echo "Detection modules are ON — expect ~55 msg/s and p95 ~4.3s."
  elif [ "$enabled" -eq 0 ]; then
    echo "Detection modules are OFF — expect ~130 msg/s and p95 ~0.65s."
  else
    echo "Mixed state: $enabled of ${#MODULES[@]} enabled."
  fi
}

apply() {
  echo "Recreating rspamd and elemta so the change takes effect..."
  docker compose -f "$COMPOSE" up -d --force-recreate elemta-rspamd elemta >/dev/null
  echo "Waiting for health..."
  sleep 25
  docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'elemta-rspamd|elemta-node0' || true
}

case "${1:-}" in
  on)
    for m in "${MODULES[@]}"; do
      python3 - "$COMPOSE" "$m" "$MARKER" <<'PY'
import sys
path, mod, marker = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
line = f"      - ../../docker/rspamd/override.d/{mod}.conf:/etc/rspamd/override.d/{mod}.conf:ro\n"
if line in s:
    s = s.replace(line, f"      {marker}\n      # -{line.strip()[7:]}\n", 1)
    open(path, "w").write(s)
PY
    done
    echo "Detection modules enabled."
    apply; status
    ;;
  off)
    for m in "${MODULES[@]}"; do
      python3 - "$COMPOSE" "$m" "$MARKER" <<'PY'
import sys
path, mod, marker = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
commented = f"      {marker}\n      # - ../../docker/rspamd/override.d/{mod}.conf:/etc/rspamd/override.d/{mod}.conf:ro\n"
plain = f"      - ../../docker/rspamd/override.d/{mod}.conf:/etc/rspamd/override.d/{mod}.conf:ro\n"
if commented in s:
    s = s.replace(commented, plain, 1)
    open(path, "w").write(s)
PY
    done
    echo "Detection modules disabled (fast, offline default restored)."
    apply; status
    ;;
  status) status ;;
  *) usage ;;
esac
