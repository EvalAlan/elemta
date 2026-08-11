#!/bin/sh
set -eu

lab_dir="${MAILAUTH_LAB_DIR:-/tmp/elemta-mailauth-lab}"
mkdir -p "$lab_dir"

if [ ! -s "$lab_dir/mailauth.key" ]; then
    openssl genrsa -out "$lab_dir/mailauth.key" 2048 >/dev/null 2>&1
fi
# This is a throwaway fixture under /tmp, not a production key. The image runs
# as uid 1001 and a bind mount preserves host ownership, so it must be readable
# long enough for prepare-config.sh to stage its own 0600 runtime copy.
chmod 644 "$lab_dir/mailauth.key"

public_key=$(openssl pkey -in "$lab_dir/mailauth.key" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
python3 scripts/dev/prepare_mailauth_lab.py config/elemta.toml "$lab_dir" "$public_key"
chmod 644 "$lab_dir/elemta-generated.toml" "$lab_dir/Corefile" "$lab_dir/auth.test.zone"
echo "$lab_dir"
