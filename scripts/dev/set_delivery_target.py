#!/usr/bin/env python3
"""Repoint [delivery] host/port in config/elemta.toml.

Scoped to the [delivery] table on purpose. `host` and `port` are generic enough
that a regex over the whole file works right up until someone adds a `host =`
to a section that appears earlier, at which point it silently rewrites the
wrong setting and the mail server quietly delivers somewhere unexpected. This
repository has already been bitten twice by TOML keys landing in the wrong
table; that is not a trap worth rebuilding.

  python3 scripts/dev/set_delivery_target.py elemta-sink 2424
"""

import re
import sys

CONFIG = "config/elemta.toml"


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: set_delivery_target.py <host> <port>")
    host, port = sys.argv[1], sys.argv[2]
    if not port.isdigit():
        sys.exit(f"port must be numeric, got {port!r}")

    lines = open(CONFIG).read().splitlines(keepends=True)
    section, changed = None, {"host": False, "port": False}
    for index, line in enumerate(lines):
        header = re.match(r"^\s*\[([^\]]+)\]", line)
        if header:
            section = header.group(1)
            continue
        if section != "delivery":
            continue
        if re.match(r"^host\s*=", line):
            lines[index] = f'host = "{host}"\n'
            changed["host"] = True
        elif re.match(r"^port\s*=", line):
            lines[index] = f"port = {port}\n"
            changed["port"] = True

    missing = [k for k, v in changed.items() if not v]
    if missing:
        sys.exit(f"did not find {', '.join(missing)} in the [delivery] table of "
                 f"{CONFIG}; refusing to guess")

    open(CONFIG, "w").write("".join(lines))
    print(f"   delivery target: {host}:{port}")


if __name__ == "__main__":
    sys.exit(main())
