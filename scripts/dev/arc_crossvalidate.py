#!/usr/bin/env python3
"""Check Elemta's ARC implementation against an independent one.

Elemta implements RFC 8617 itself rather than depending on one of the two
essentially unadopted Go ARC libraries. That decision is only defensible if the
implementation is checked against something that was not written here: a signer
tested solely against its own verifier proves that the two agree, not that
either is right. A canonicalization mistake made consistently in both
directions passes every self-round-trip test ever written.

dkimpy is the reference here. It is long-established, independently written, and
implements both halves of ARC, so it can verify what we seal and seal what we
verify.

Run:  python3 scripts/dev/arc_crossvalidate.py
Needs: a virtualenv with dkimpy, and a Go toolchain. Neither is a build or CI
dependency; this is a check you run when you change the ARC code.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# dkimpy's arc_sign builds its AAR from an existing Authentication-Results
# header whose authserv-id matches, and silently signs nothing when there is
# none — so the message must carry one or half this script tests an unsealed
# message and reports success.
MESSAGE = (
    b"Authentication-Results: example.com; spf=pass smtp.mailfrom=example.com\r\n"
    b"From: sender@example.com\r\n"
    b"To: recipient@example.net\r\n"
    b"Subject: cross validation\r\n"
    b"Date: Tue, 11 Aug 2026 12:00:00 -0400\r\n"
    b"Message-ID: <cross@example.com>\r\n"
    b"\r\n"
    b"Body text that both implementations must hash identically.\r\n"
)

DOMAIN = "example.com"
SELECTOR = "arc"

failures = []


def report(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")
    if not ok:
        failures.append(name)


def make_key(workdir):
    """Generate an RSA keypair and the DKIM TXT record that publishes it."""
    key_path = os.path.join(workdir, "arc.key")
    subprocess.run(
        ["openssl", "genrsa", "-out", key_path, "2048"],
        check=True, capture_output=True,
    )
    os.chmod(key_path, 0o600)
    der = subprocess.run(
        ["openssl", "rsa", "-in", key_path, "-pubout", "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    record = "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()
    zone = json.dumps({f"{SELECTOR}._domainkey.{DOMAIN}": [record]})
    return key_path, zone, record


def go_seal(binary, key_path, zone, message, auth_results):
    return subprocess.run(
        [binary, "seal", "-key", key_path, "-zone", zone,
         "-domain", DOMAIN, "-selector", SELECTOR, "-ar", auth_results],
        input=message, check=True, capture_output=True,
    ).stdout


def go_verify(binary, zone, message):
    result = subprocess.run(
        [binary, "verify", "-zone", zone],
        input=message, capture_output=True,
    )
    return result.stdout.decode().strip().split("\t")[0]


def main():
    try:
        import dkim
    except ImportError:
        print("dkimpy is not installed. Create a venv and 'pip install dkimpy'.")
        return 2

    workdir = tempfile.mkdtemp(prefix="arc-cross-")
    key_path, zone, record = make_key(workdir)

    binary = os.path.join(workdir, "arctool")
    subprocess.run(
        ["go", "build", "-o", binary, "./scripts/dev/arctool"],
        cwd=REPO, check=True,
    )

    def dnsfunc(name, timeout=5):
        wanted = f"{SELECTOR}._domainkey.{DOMAIN}"
        if isinstance(name, bytes):
            name = name.decode()
        if name.rstrip(".") == wanted:
            return record.encode()
        return b""

    print("Elemta seals, dkimpy verifies:")
    sealed = go_seal(binary, key_path, zone, MESSAGE, "example.com; spf=pass smtp.mailfrom=example.com")
    cv, results, reason = dkim.arc_verify(sealed, dnsfunc=dnsfunc)
    cv = cv.decode() if isinstance(cv, bytes) else str(cv)
    report("dkimpy accepts our seal", "pass" in cv.lower(), f"cv={cv} reason={reason}")

    # A verifier that accepts everything would also "pass" here, so prove dkimpy
    # rejects a tampered version of the same message.
    tampered = sealed.replace(b"Body text", b"Edited text")
    cv_t, _, _ = dkim.arc_verify(tampered, dnsfunc=dnsfunc)
    cv_t = cv_t.decode() if isinstance(cv_t, bytes) else str(cv_t)
    report("dkimpy rejects our seal once the body is edited", "pass" not in cv_t.lower(), f"cv={cv_t}")

    print("dkimpy seals, Elemta verifies:")
    with open(key_path, "rb") as handle:
        privkey = handle.read()
    their_headers = [b"from", b"to", b"subject", b"date", b"message-id"]
    their_sets = dkim.arc_sign(
        MESSAGE, SELECTOR.encode(), DOMAIN.encode(), privkey,
        b"example.com", include_headers=their_headers,
    )
    # arc_sign returns [] rather than raising when it decides it cannot sign.
    # Without this guard every check below runs against an unsealed message and
    # reports success, which is worse than no check at all.
    if len(their_sets) != 3:
        report("dkimpy produced a complete ARC set", False,
               f"got {len(their_sets)} headers, expected 3 — the rest of this run would be meaningless")
        print()
        print("Cross-validation could not run.")
        return 1
    their_sealed = b"".join(their_sets) + MESSAGE
    report("we accept dkimpy's seal", go_verify(binary, zone, their_sealed) == "pass")

    their_tampered = their_sealed.replace(b"Body text", b"Edited text")
    report("we reject dkimpy's seal once the body is edited",
           go_verify(binary, zone, their_tampered) != "pass")

    print("Two implementations, one chain:")
    # Our set layered on top of theirs is the realistic forwarding case, and the
    # one most likely to expose a disagreement about the seal's signing scope.
    both = go_seal(binary, key_path, zone, their_sealed, "example.com; arc=pass")
    report("we can seal on top of dkimpy's chain", go_verify(binary, zone, both) == "pass")
    cv_b, _, reason_b = dkim.arc_verify(both, dnsfunc=dnsfunc)
    cv_b = cv_b.decode() if isinstance(cv_b, bytes) else str(cv_b)
    report("dkimpy accepts the two-hop chain", "pass" in cv_b.lower(), f"cv={cv_b} reason={reason_b}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("All cross-validation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
