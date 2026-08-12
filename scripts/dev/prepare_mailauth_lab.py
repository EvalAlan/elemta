#!/usr/bin/env python3
"""Build the generated config and DNS zone for the local mail-auth lab."""

import pathlib
import re
import sys


def set_key(text: str, section: str, key: str, value: str) -> str:
    section_re = re.compile(
        r"^\[" + re.escape(section) + r"\]\s*$(.*?)(?=^\[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = section_re.search(text)
    if not match:
        return text.rstrip() + f"\n\n[{section}]\n{key} = {value}\n"
    body = match.group(1)
    key_re = re.compile(r"^(\s*)" + re.escape(key) + r"\s*=.*$", re.MULTILINE)
    if key_re.search(body):
        body = key_re.sub(lambda m: f"{m.group(1)}{key} = {value}", body, count=1)
    else:
        body = body.rstrip() + f"\n{key} = {value}\n"
    return text[: match.start(1)] + body + text[match.end(1) :]


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: prepare_mailauth_lab.py SOURCE_CONFIG OUTPUT_DIR PUBLIC_KEY_BASE64", file=sys.stderr)
        return 2
    source = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    public_key = sys.argv[3].strip()
    out.mkdir(parents=True, exist_ok=True)

    text = source.read_text(encoding="utf-8")
    changes = {
        # split, not smtp: local mail still reaches the mailbox server over
        # LMTP while anything else goes out over SMTP to the sink, so one stack
        # exercises both paths instead of trading one for the other.
        ("delivery", "mode"): '"split"',
        ("plugins.spf", "enabled"): "true",
        ("plugins.dkim", "enabled"): "true",
        ("plugins.dkim", "verify"): "true",
        ("plugins.dkim", "sign"): "true",
        ("plugins.dkim", "domains"): '[{ domain = "pass.auth.test", selector = "mail", private_key_path = "/app/runtime-config/mailauth.key" }]',
        ("plugins.dmarc", "enabled"): "true",
        ("plugins.dmarc", "enforce"): "false",
        ("plugins.arc", "enabled"): "true",
        ("plugins.arc", "verify"): "true",
        ("plugins.arc", "seal"): "true",
        ("plugins.arc", "domain"): '"auth.test"',
        ("plugins.arc", "selector"): '"arc"',
        ("plugins.arc", "private_key_path"): '"/app/runtime-config/mailauth.key"',
    }
    for (section, key), value in changes.items():
        text = set_key(text, section, key, value)
    (out / "elemta-generated.toml").write_text(text, encoding="utf-8")

    (out / "Corefile").write_text(
        "auth.test:53 {\n    file /zones/auth.test.zone\n    log\n    errors\n}\n"
        ".:53 {\n    forward . 1.1.1.1 8.8.8.8\n    errors\n}\n",
        encoding="utf-8",
    )
    zone = f"""$ORIGIN auth.test.
$TTL 30
@ IN SOA ns.auth.test. hostmaster.auth.test. 1 30 30 30 30
@ IN NS ns.auth.test.
ns IN A 172.31.0.53
smtp IN A 172.31.0.25
receiver IN MX 10 smtp.auth.test.
pass IN TXT "v=spf1 +all"
fail IN TXT "v=spf1 -all"
_dmarc.pass IN TXT "v=DMARC1; p=reject; adkim=s; aspf=s"
_dmarc.fail IN TXT "v=DMARC1; p=reject; adkim=s; aspf=s"
mail._domainkey.pass IN TXT "v=DKIM1; k=rsa; p={public_key}"
arc._domainkey IN TXT "v=DKIM1; k=rsa; p={public_key}"
"""
    (out / "auth.test.zone").write_text(zone, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
