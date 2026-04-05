# Security Policy

## Supported versions

Security fixes are prioritized for:

- `main` (latest)

Older branches may receive fixes at maintainer discretion.

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories (preferred) or direct maintainer contact.

Include:

- affected version/commit
- impact
- reproduction steps or proof of concept
- suggested remediation (optional)

Please do **not** post exploitable details in public issues before a fix is available.

## Response targets

Best effort targets:

- Initial triage: within 72 hours
- Severity assessment: within 7 days
- Patch timeline: depends on severity and exploitability

## Hardening baseline for production

- Run current Go patch release and current Elemta main release
- Keep TLS verification enabled for outbound delivery unless explicitly required otherwise
- Use least-privilege file permissions for config, queue, and secrets
- Isolate API/web surfaces behind auth + network controls
- Monitor queue, auth failures, and anomalous connection spikes

## Coordinated disclosure

We support coordinated disclosure and will credit reporters (if requested) after patches are released.
