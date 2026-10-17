# Mail administration

Mailbox administration is available through **Mail Administration** in the
existing dashboard and `elemta provision` on the server. Both use the same
service and directory. The console has a domain browser, searchable account
and alias tables, and account details for names, status, quotas, aliases and
password resets. Dashboard administrators are separate from mailbox users;
`elemta user` continues to manage dashboard logins.

## Commands

Use the running service's configuration, including its shared runtime volume:

```sh
elemta --config /path/to/elemta.toml provision list-domains
elemta --config /path/to/elemta.toml provision create-account dana@example.com --name 'Dana Jones' --quota 5G
elemta --config /path/to/elemta.toml provision get-account dana@example.com
elemta --config /path/to/elemta.toml provision modify-account dana@example.com --status disabled
elemta --config /path/to/elemta.toml provision modify-account dana@example.com --status active --quota 10G
elemta --config /path/to/elemta.toml provision set-password dana@example.com
elemta --config /path/to/elemta.toml provision add-alias dana@example.com sales@example.com
elemta --config /path/to/elemta.toml provision remove-alias dana@example.com sales@example.com
elemta --config /path/to/elemta.toml provision --json list-accounts
```

Short command aliases are `ca`, `ga`, `gaa`, `ma`, `da`, `sp`, `aaa`, `raa`,
`gad`, `cd`, and `dd`, respectively for create/get/list/modify/delete account,
set password, add/remove alias, list/create/delete domain. `--json` returns
machine-readable output on stdout; diagnostics and audit logs use stderr.

Create-account and set-password prompt twice on a terminal. With redirected
stdin they read one line, allowing a secret manager to supply the password
without exposing it in command arguments. There is no password argument or
password flag. Initial passwords are applied with LDAP Password Modify and the
directory's own policy. A new account stays disabled until its password is set.
Passwords and stored password hashes are never included in account responses.

Quota sizes accept integer bytes or suffixes such as `K`, `M`, `G`, `MiB`, and
`GiB`. Suffixes use binary units; `5G` is 5 GiB. Zero means unlimited. Quotas
are enforced by the mailbox server, including IMAP APPEND and delivery; updated
limits apply when a new mail session starts. The current development mapping
uses the shared vmail UID/GID 5000 and one Maildir per primary address.

Disabling an account prevents new IMAP and SMTP authentication and delivery.
It revokes existing webmail sessions and outstanding recovery links, preserving
its verified recovery email for later reactivation. Existing external IMAP or
SMTP connections can continue until the mail server closes them. Deleting an
account additionally clears recovery ownership, so a future owner cannot be
reclaimed through the previous owner's recovery address. Deletion retains
mailbox files; recreation of the same address can expose that retained mail,
so retain, archive or purge those files according to the operator's policy.

```sh
elemta --config /path/to/elemta.toml provision delete-account dana@example.com --confirm dana@example.com
```

Delivery aliases point to one primary mailbox. They do not create another
Maildir or another mailbox password. Mail apps sign in using the primary
address. An alias does not automatically grant permission to send with that
address; outbound sender permissions remain governed by `[auth.sender_aliases]`.

## Domains and routing

```sh
elemta --config /path/to/elemta.toml provision create-domain example.net
elemta --config /path/to/elemta.toml provision delete-domain example.net
```

These edit `local_domains` in the existing TOML document, preserving comments
and unrelated configuration. A shared sidecar lock serializes provisioning
and dashboard config writes. Domain removal is refused if accounts or aliases
still use it, and the last configured domain cannot be removed. Domain routing
changes require an **SMTP service restart**; the CLI and console both say so.
DNS, MX records, certificates and signing keys must be configured separately.

Account/alias/status changes update a shared `.provision-generation` sidecar.
The SMTP verifier discards both positive and negative recipient lookup caches
when its generation changes. This prevents stale unknown-recipient refusals
for newly added addresses, and stale acceptance of deleted recipients.

## Directory and mailbox configuration

Administration uses `[webmail] ldap_url`, `ldap_base`, `ldap_reset_dn` and
`ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD`, together with the existing shared Valkey
session configuration. The directory bind needs account creation, attribute
updates, password modification and deletion permissions under the mailbox
base, plus access to `ou=mail-addresses` beside it. That subtree reserves
addresses atomically across CLI and dashboard processes. Keep this service
account separate from the read-only LDAP lookup account. The runtime config
and its sidecars must be writable and shared by the CLI, dashboard and SMTP
service. Use LDAPS in production; the shipped plain LDAP setup is dev-only.

The standard `mailAlternateAddress`, `accountStatus`, and `mailQuotaSize`
attribute definitions are in `docker/ldap/10-mail-schema.ldif`. They use the
registered attribute OIDs from the published
[mail directory schema](https://github.com/amery/qmail/blob/master/qmail.schema).
The development LDAP initializer installs this subset if the attributes are
absent. An existing directory that already provides them should keep its own
schema. The provisioning service uses the standard `extensibleObject` auxiliary
class and an explicit field allowlist rather than accepting arbitrary LDAP
attribute writes. Existing accounts with no accountStatus are treated as active;
missing mailQuotaSize means unlimited.

The development Dovecot configuration maps aliases to the primary `mail`
attribute for LMTP, rejects inactive accounts, and reads `mailQuotaSize` for its
count quota backend. External mailbox servers need equivalent mappings; see
[Dovecot LDAP mappings](https://doc.dovecot.org/2.4.1/core/config/auth/databases/ldap.html),
[quota configuration](https://doc.dovecot.org/2.4.1/core/plugins/quota.html), and
[default values in variable expansion](https://doc.dovecot.org/2.4.1/core/settings/variables.html).
The SMTP LDAP authenticator applies the same active-status rule.

## Admin API and permissions

`/api/provision/status`, `/accounts`, `/accounts/{address}`, the account
`/password` and `/aliases` actions, and `/domains` back the console. These
routes require dashboard authentication and `system:admin`, including reads.
They remain closed when dashboard authentication is disabled. Mutations require
JSON and existing same-origin write protection. Successful changes record the
actor, action and target, without passwords or recovery tokens. Distribution
lists and delegated administration are outside this version's command surface.

Verification includes service validation and configuration-lock tests, admin
API permissions and lifecycle tests, CLI output/alias tests, SMTP cache tests,
and real LDAP/IMAP/SMTP checks against the development stack.
