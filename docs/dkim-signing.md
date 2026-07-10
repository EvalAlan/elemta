# Outbound DKIM Signing

Elemta can DKIM-sign outbound mail so that receiving providers
(Gmail, Yahoo, Outlook, etc.) can verify the message originated from a domain
you control. Signing measurably improves deliverability and is effectively a
prerequisite for bulk sending to the large mailbox providers.

This document covers the outbound **signing** path. Inbound DKIM/DMARC/ARC
**verification** is handled separately by the plugin system.

## How it works

- Signing happens on the **remote SMTP delivery path** (delivery to a remote
  MX), inside `SMTPDeliveryHandler`. Local LMTP delivery (e.g. to Dovecot) is
  intentionally **not** signed, because a locally delivered copy never crosses
  an administrative boundary where DKIM matters.
- A message is signed **once**, before recipients are grouped by domain, so the
  exact same signed bytes are delivered to every recipient MX.
- Signing is **idempotent**. If a message already carries a `DKIM-Signature`
  for the chosen signing domain, it is left untouched, so a delivery **retry
  never double-signs**.
- The signing domain is selected by matching the **envelope-from** domain
  against the configured domains. When the envelope-from is empty (for example,
  a bounce/DSN with a null return path), the **From header** domain is used as a
  fallback. If no key is configured for the resolved domain, the message is
  delivered **unsigned** and a debug line is logged.
- If signing fails for any reason, the message is delivered **unsigned** (with a
  warning log) rather than being failed outright.

The signer reuses [`github.com/emersion/go-msgauth/dkim`](https://pkg.go.dev/github.com/emersion/go-msgauth/dkim),
the same library referenced by the verification code, so a message signed by
elemta verifies with the identical implementation.

## Generating keys

RSA (2048-bit is the widely interoperable choice):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out /etc/elemta/dkim/example.com.key
chmod 600 /etc/elemta/dkim/example.com.key
```

Ed25519 (smaller signatures; publish an additional RSA selector for receivers
that do not yet support Ed25519):

```sh
openssl genpkey -algorithm ed25519 -out /etc/elemta/dkim/example.com.ed25519.key
chmod 600 /etc/elemta/dkim/example.com.ed25519.key
```

Both PKCS#1 and PKCS#8 encoded keys are accepted.

### Key file permissions

Elemta refuses to start if a private key is readable or writable by group or
other (any of the `0077` permission bits set), matching the repo's file-security
posture. Keep keys at mode `0600` (or `0400`), owned by the elemta user.

## Publishing the public key in DNS

Extract the public key and publish it as a TXT record at
`<selector>._domainkey.<domain>`:

```sh
openssl rsa -in /etc/elemta/dkim/example.com.key -pubout 2>/dev/null \
  | grep -v '^-----' | tr -d '\n'
```

Then create a DNS TXT record, e.g. for selector `mail` on `example.com`:

```
mail._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=<base64-public-key>"
```

For Ed25519 use `k=ed25519` and the base64 of the raw 32-byte public key.

## Configuration

Add a top-level `[dkim]` section:

```toml
[dkim]
enabled = true
header_canonicalization = "relaxed"   # default: relaxed
body_canonicalization = "relaxed"     # default: relaxed

  [[dkim.domains]]
  domain = "example.com"
  selector = "mail"
  private_key_path = "/etc/elemta/dkim/example.com.key"

  [[dkim.domains]]
  domain = "example.net"
  selector = "s2026"
  private_key_path = "/etc/elemta/dkim/example.net.key"
  # Optional per-domain override of the signed headers.
  headers_to_sign = ["From", "To", "Subject", "Date", "Message-ID"]
```

### Fields

| Field | Scope | Description |
|-------|-------|-------------|
| `enabled` | `[dkim]` | Master switch. When `false` (or the section is absent), no outbound signing occurs. |
| `header_canonicalization` | `[dkim]` | `relaxed` (default) or `simple`. |
| `body_canonicalization` | `[dkim]` | `relaxed` (default) or `simple`. |
| `domain` | `[[dkim.domains]]` | The signing domain (the `d=` tag). |
| `selector` | `[[dkim.domains]]` | The DKIM selector (the `s=` tag). |
| `private_key_path` | `[[dkim.domains]]` | Path to the PEM RSA or Ed25519 private key. |
| `headers_to_sign` | `[[dkim.domains]]` | Optional. Overrides the default signed header set for this domain. |

Default signed headers (when `headers_to_sign` is omitted): `From`, `To`, `Cc`,
`Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type`, `Reply-To`,
`In-Reply-To`, `References`.

## Verifying it works

Send a message to a Gmail account and check **Show original**; the DKIM result
should read `PASS`. Command-line tooling such as `opendkim-testkey`,
`dig TXT <selector>._domainkey.<domain>`, or an auto-responder like
`check-auth@verifier.port25.com` can confirm both the DNS record and live
signature validity.
