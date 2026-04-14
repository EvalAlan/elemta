#!/usr/bin/env python3
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: configure_queue_backend.py <backend> [postgres_dsn] [config_path]", file=sys.stderr)
        return 2

    backend = sys.argv[1].strip().lower()
    dsn = (sys.argv[2].strip() if len(sys.argv) > 2 else "")
    config_path = Path(sys.argv[3] if len(sys.argv) > 3 else "config/elemta.toml")

    if backend not in {"file", "sqlite", "postgres"}:
        print(f"invalid backend '{backend}', expected file|sqlite|postgres", file=sys.stderr)
        return 2

    text = config_path.read_text()

    text, n = re.subn(r'(?m)^backend\s*=\s*"[^"]*"\s*$', f'backend = "{backend}"', text, count=1)
    if n == 0:
        print("failed to find queue backend line in config", file=sys.stderr)
        return 1

    pg_block_pattern = re.compile(r'(?ms)^\[queue\.postgres\]\n.*?(?=^\[|\Z)')
    existing = pg_block_pattern.search(text)
    existing_dsn = ""
    if existing:
        m = re.search(r'(?m)^dsn\s*=\s*"([^"]*)"\s*$', existing.group(0))
        if m:
            existing_dsn = m.group(1)

    if not dsn:
        dsn = existing_dsn or "postgres://elemta:elemta@127.0.0.1:5432/elemta_queue?sslmode=disable"

    new_pg_block = (
        "[queue.postgres]\n"
        f"dsn = \"{dsn}\"\n"
        "max_open_conns = 20\n"
        "max_idle_conns = 10\n"
        "conn_max_lifetime_seconds = 1800\n\n"
    )

    if existing:
        text = pg_block_pattern.sub(new_pg_block, text, count=1)
    else:
        marker = "\n[logging]\n"
        if marker in text:
            text = text.replace(marker, "\n" + new_pg_block + "[logging]\n", 1)
        else:
            text += "\n" + new_pg_block

    config_path.write_text(text)
    print(f"Updated {config_path} -> backend={backend}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
