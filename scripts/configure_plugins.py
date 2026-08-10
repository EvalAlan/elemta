#!/usr/bin/env python3
"""Turn the bundled plugins on (or off) in a configuration file.

A development stack whose plugins are all switched off exercises none of them,
so the first time anyone finds out a plugin is broken is when they turn it on in
production. `make install-dev` therefore enables everything by default.

Each plugin can be overridden individually — `make install-dev PLUGIN_RBL=off`
— because "everything on" is a sensible default, not a rule.

Edits are surgical: only the keys named here are touched, so comments, ordering
and every setting this script has never heard of survive. The same reasoning as
internal/config/toml_edit.go, which exists because regenerating the file from
defaults silently dropped whole sections.
"""

import re
import sys


# The value written for each plugin when it is enabled. A plugin with a
# prerequisite gets it here, because "enabled" without it is a filter the
# operator believes is protecting them — and the server refuses to start that
# way, which would turn a dev deploy into a debugging session.
PLUGIN_SETTINGS = {
    "rate_limiter": {"section": "rate_limiter", "keys": {}},
    "clamav": {"section": "antivirus", "keys": {}, "also": ["antivirus.clamav"]},
    "rspamd": {"section": "antispam", "keys": {}, "also": ["antispam.rspamd"]},
    "access_control": {"section": "access_control", "keys": {}},
    "rbl": {
        "section": "rbl",
        # Spamhaus is the default because it is the list most people mean.
        #
        # reject stays off: a blocklist that starts refusing mail the moment a
        # dev stack comes up is one nobody will trust. Tag mode adds an
        # X-RBL-Listed header so the operator can see what it would have refused
        # first. Note that querying Spamhaus through a public resolver returns a
        # status code about the querier rather than about the sender — Elemta
        # ignores those deliberately and logs why.
        "keys": {"zones": '["zen.spamhaus.org"]', "reject": "false"},
    },
    "mass_mailer": {"section": "mass_mailer", "keys": {}},
}


def set_key(text: str, section: str, key: str, value: str) -> str:
    """Set key to value inside [section], adding either if missing."""
    section_re = re.compile(
        r"^\[" + re.escape(section) + r"\]\s*$(.*?)(?=^\[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = section_re.search(text)
    if not match:
        # A section that is not there yet is appended rather than skipped: the
        # alternative is a plugin the deploy claims to have enabled and did not.
        return text.rstrip("\n") + f"\n\n[{section}]\n{key} = {value}\n"

    body = match.group(1)
    key_re = re.compile(r"^(\s*)" + re.escape(key) + r"\s*=.*$", re.MULTILINE)
    if key_re.search(body):
        new_body = key_re.sub(lambda m: f"{m.group(1)}{key} = {value}", body, count=1)
    else:
        new_body = body.rstrip("\n") + f"\n{key} = {value}\n"

    return text[: match.start(1)] + new_body + text[match.end(1) :]


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: configure_plugins.py <config.toml> <plugin=on|off> ...", file=sys.stderr)
        return 2

    path = sys.argv[1]
    wanted = {}
    for arg in sys.argv[2:]:
        name, _, state = arg.partition("=")
        if name not in PLUGIN_SETTINGS:
            print(f"unknown plugin {name!r}", file=sys.stderr)
            return 2
        wanted[name] = state.lower() in ("on", "true", "1", "yes")

    with open(path, encoding="utf-8") as handle:
        text = handle.read()

    for name, enabled in sorted(wanted.items()):
        spec = PLUGIN_SETTINGS[name]
        flag = "true" if enabled else "false"

        text = set_key(text, spec["section"], "enabled", flag)
        # A scanner is gated twice — by its stage and by the scanner itself —
        # and setting only one of them leaves it off while the config reads as
        # though it is on.
        for extra in spec.get("also", []):
            text = set_key(text, extra, "enabled", flag)

        # Prerequisites are written only when switching on, so turning a plugin
        # off does not quietly discard the settings it will need next time.
        if enabled:
            for key, value in spec["keys"].items():
                text = set_key(text, spec["section"], key, value)

        print(f"  {name}: {'enabled' if enabled else 'disabled'}")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
