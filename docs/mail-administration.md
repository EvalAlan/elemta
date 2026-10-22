# Mail administration

Mailbox administration is available through **Mail Administration** in the
existing dashboard and `elemta provision` on the server. Both use the same
service and directory. The console has a domain browser, searchable account
and alias tables, and account details for names, status, quotas, aliases and
password resets. Dashboard administrators are separate from mailbox users;
`elemta user` continues to manage dashboard logins.

## Open mailbox

An administrator can select an active account in **Mail Administration** and
choose **Open mailbox**. A new webmail tab opens with a banner naming the
administrator, the account, and the access end time. Domain administrators can
open only accounts in their assigned domains. Each issue is recorded in the
mailbox audit log as `mailbox-open` with the administrator, client address,
target account, and expiry.

The credential is limited to that one account and expires after one hour;
the webmail session ends at the same time, even if it remains active. It works
only on webmail's internal IMAP connection. Public IMAP, POP3, SMTP submission,
DAV, and shared mailboxes refuse it. Webmail hides sending actions and refuses
compose and other sending routes for this session. It does not notify the
account owner. The administrator can manage mail in the opened account.

Set `ELEMTA_WEBMAIL_PUBLIC_URL` on the dashboard service to the public webmail
origin (for example, `https://mail.example.com`). The production Compose
overlay derives it from `MAIL_DOMAIN`; the local Compose default is
`http://localhost:8027`. The dashboard sends the short-lived credential to
webmail in a form POST so it does not appear in a URL or browser history.

## Commands

Use the running service's configuration, including its shared runtime volume:

```sh
elemta --config /path/to/elemta.toml provision list-domains
elemta --config /path/to/elemta.toml provision create-account dana@example.com --name 'Dana Jones' --quota 5G
elemta --config /path/to/elemta.toml provision get-account dana@example.com
elemta --config /path/to/elemta.toml provision modify-account dana@example.com --status disabled
elemta --config /path/to/elemta.toml provision modify-account dana@example.com --status active --quota 10G
elemta --config /path/to/elemta.toml provision modify-account dana@example.com --forward dana@home.example --keep-copy
elemta --config /path/to/elemta.toml provision modify-account dana@example.com --send-as sales@example.com,@brand.example
elemta --config /path/to/elemta.toml provision set-password dana@example.com
elemta --config /path/to/elemta.toml provision reset-two-factor dana@example.com
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

An account has one of three statuses (`modify-account --status`, or the
account dialog in the dashboard):

| Status | Sign-in (webmail, IMAP, POP3, SMTP, CalDAV/CardDAV, app passwords) | Incoming mail |
|---|---|---|
| `active` | allowed | delivered |
| `suspended` | refused | delivered |
| `disabled` | refused | refused (550 at RCPT) |

Suspend an account that must stop being used at once (a leaked password, a
departing employee, an unpaid bill) while its mail keeps arriving: nothing
bounces, and reactivating it finds everything in place. Suspending or
disabling ends its webmail sessions immediately. A suspended account stays in
the company address book and can still be opened by an administrator ("Open
mailbox"); a disabled one can't, and it can't be opened as a shared mailbox.

`reset-two-factor` removes an account's authenticator enrollment, pending setup
and recovery codes. An administrator should verify the user's identity before
running it. The CLI records the reset in the audit log. If the account's class
requires two-step verification, the next webmail sign-in requires fresh setup.

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

## Classes of service

A class of service is a named set of rules for what an account may do.
Every domain can name the class its accounts use by default, and an account
can name its own class and override single settings. Each setting is worked
out separately, most specific first:

account override > account's class > domain's class > `default` class > built-in default

The built-in default allows everything and limits nothing, so an install
without classes behaves as before. The `default` class always exists and
can't be deleted. A class still used by an account or domain can't be
deleted either.

| Setting | Flag | Enforced by |
|---|---|---|
| Quota | `--quota 5G` | mailbox: delivery, IMAP APPEND |
| Largest message | `--max-message 25M` | mailbox for mail received, MTA for mail sent |
| Largest attachment | `--max-attachment 10M` | the same; measured after decoding, so 10M lets a 10 MB file through |
| Messages per hour | `--messages-per-hour 200` | MTA, for a signed-in sender |
| Recipients per message | `--recipients-per-message 100` | MTA, at RCPT |
| Recipients per day | `--recipients-per-day 1000` | MTA, at RCPT |
| Address book | `--address-book on` | webmail: offers the accounts and lists of the user's domain as they type an address. Off unless a class turns it on |
| Forwarding addresses | `--max-forward-addresses 1` | dashboard, CLI and webmail when forwarding is set; mailbox: only that many get a copy. 3 unless a class sets it; at most 50, which `0` also means |
| Protocols | `--protocols pop3=off,imap=on` | `imap`, `pop3`: mailbox sign-in; `webmail`, `dav`: webmail; `submission`: MTA |
| External forwarding | `--external-forwarding off` | mailbox: a filter redirecting outside the server keeps the mail instead |
| Filters | `--filters off` | mailbox: stored filters are ignored and ManageSieve refuses; turning filters back on restores them |
| Require app passwords | `--require-app-passwords on` | mail apps must use app passwords, as if the user had chosen it |
| Require two-step verification | `--require-two-factor on` | webmail: sign-in leads through setting it up, and it can't be turned off |
| Empty Trash | `--trash-days 30` | mailbox: hourly, mail in Trash longer than this is deleted |
| Empty Junk | `--junk-days 14` | the same, for Junk |
| Retention | `--retention-days 2555` | mailbox: hourly, mail in any folder older than this (by its date) is deleted |
| Legal hold | `--legal-hold on` | mailbox: nothing the user deletes is lost (see below) |

Sizes accept the same suffixes as quotas; for every limit `0` means
unlimited. Every flag also takes `inherit`, which unsets the value so the
next layer decides. A quota set on the account itself (`--quota` on
create-account or modify-account) outranks the classes; only the account's
policy override beats it.

```sh
provision set-class staff --description 'Staff' --quota 10G --max-attachment 25M --messages-per-hour 500
provision set-class interns --quota 2G --protocols pop3=off,submission=off --external-forwarding off
provision list-classes
provision get-class staff
provision set-domain-class example.com staff
provision set-policy dana@example.com --class interns --messages-per-hour 50
provision get-policy dana@example.com     # stored policy, and what applies with where each value came from
provision set-domain-class example.com inherit
provision delete-class interns
```

Sending limits count messages per clock hour and recipients per UTC day, per
user. Mail sent from the webmail counts too. With `VALKEY_ADDR` set on the
MTA, all nodes share one count; otherwise each node counts on its own. A
sender over a limit gets a temporary refusal (4xx), so their mail program
tries again later. If the MTA can't read a sender's policy, it also asks
them to try later rather than sending unchecked. Changes reach the MTA within
a minute and the mailbox at the next sign-in or delivery.

Classes and policy are kept by the mailbox service. The CLI, the dashboard
and the MTA reach them through its admin API on the internal health port,
which is open only to `lmtp_allowed_networks` and needs a shared token,
`ELEMTA_MAILBOX_ADMIN_TOKEN`. Clients find the API at
`ELEMTA_MAILBOX_ADMIN_URL`, or at `[auth] mailbox_security_url` (the same
port). Without the token the API is off and so are classes of service.
`scripts/dev-secrets.sh` generates the token for the development stacks.

## Distribution lists, domain aliases and catch-all

Beyond accounts and their aliases, an address can be a distribution list, a
name at an alias domain, or fall through to a domain's catch-all. The
mailbox service resolves every local recipient in this order:

1. an account, or one of its aliases (the directory);
2. a distribution list;
3. the same name at the domain this one is an alias of (its accounts,
   aliases and lists);
4. that domain's catch-all.

The MTA's recipient check asks the mailbox, so these rules also decide what
the MTA accepts. A disabled account keeps its address: its mail is refused,
not handed to the catch-all.

**Plus addressing.** `name+anything@example.com` is delivered as
`name@example.com` (an account, an alias or a list) when the tagged address
isn't itself taken, so people can give each sign-up its own address. The
message keeps the address it was sent to, so filters can sort by the tag
(Sieve's `subaddress` extension, `:detail`).

```sh
provision create-list team@example.com --name 'Team' --owner dana@example.com --posting members \
  --members 'dana@example.com,lee@example.com,partner@other.example'
provision add-members team@example.com sam@example.com
provision remove-members team@example.com partner@other.example
provision set-list team@example.com --posting domain
provision get-list team@example.com
provision list-lists
provision delete-list team@example.com

provision create-domain-alias example.net example.com   # SMTP restart required
provision delete-domain-alias example.net
provision set-catch-all example.com dana@example.com
provision set-catch-all example.com none
provision list-domains                                   # shows alias targets and catch-alls
```

**Lists.** A list delivers to its local members directly. Each copy goes
through that member's own filters, quota and size limits, and a member
whose mailbox can't take it (full, or over their limit) is skipped
without bouncing the message for everyone else. One copy goes on to the
external members through SMTP submission, signed and queued like any
mail, with the list's owner as envelope sender, so bounces reach the
person who can fix the member list. A list without an owner sends with a
null sender, and bounces are dropped.

Lists can contain lists, up to five deep, and every address receives one
copy, aliases included. Messages get a `List-Id` header (RFC 2919) for
mail programs to file by, and a loop marker: a list that sees its own
marker again stops, so lists that include each other can't loop. A
retried delivery doesn't send twice.

`--posting` decides who may post, by envelope sender:

| Value | Who may post |
|---|---|
| `anyone` (default) | everyone, including bounces |
| `members` | the list's direct members, and its owner |
| `domain` | senders in the list's own domain, and its owner |
| `owner` | only the owner |

Other senders get a permanent refusal. A list address can't be an
account's or alias's, and the reverse; the commands check both ways. Lists
hold up to 10,000 members. External delivery needs `[sieve] submit_addr`
on the mailbox service, which filter redirects use too.

**Domain aliases.** `create-domain-alias example.net example.com` makes
every name at example.net deliver as the same name at example.com, its
lists and catch-all included. The alias becomes a local domain, so it
needs an SMTP restart like any new domain. Aliases are one step: an alias
can't point at another alias.

**Catch-all.** Mail for names nothing else claims goes to the catch-all
address, which must be an existing account, alias or list. Catch-alls
attract spam, so use them sparingly.

Per-account aliases stay in the directory (`add-alias`), as before.

## Shared mailboxes

A shared mailbox has its own account and message storage. Grant each colleague
access to that account; a grant follows both accounts' immutable directory
identities, so deleting and recreating an address does not pass its access to
the next owner. The mailbox and its members must be in the same domain.

```sh
provision create-account support@example.com --name Support
provision grant-share support@example.com dana@example.com --send
provision grant-share support@example.com lee@example.com
provision list-shares support@example.com
provision revoke-share support@example.com lee@example.com
```

The shared account must be active to receive mail. Give it an unused random
password; members use their own credentials. The grant without `--send` gives
mailbox access only. The `--send` flag also lets that member use the shared
address as the SMTP envelope sender. Grant and revoke commands appear in the
audit log. Shared mailbox administration and SMTP send-as checks require the
mailbox admin API token described above.

In webmail, a member selects the mailbox from the Mail sidebar. Messages,
folders, drafts and sent copies then belong to that mailbox. Personal settings,
contacts and calendars stay with the member. Compose uses the shared address
when the member has send permission, and their own address otherwise.

For a mail app, sign in to IMAP with a username of
`dana@example.com|support@example.com` and Dana's own password (or Dana's app
password if required by policy). Configure SMTP submission separately with
`dana@example.com` and the same credential. To send as the shared mailbox,
set the app's From address to `support@example.com`; SMTP checks the live grant.
POP3 does not expose shared mailboxes.

## Retention and legal hold

Retention rules delete old mail once an hour, on one mailbox replica at a
time, through the normal delete path, so quotas, mail apps and the webmail
see it like any other delete. Trash and Junk count from when a message
arrived in the folder; `--retention-days` counts from the message's own
date, in every folder. A first run over years of mail works through it in
batches across successive hours.

Legal hold (`set-policy dana@example.com --legal-hold on`, or on a class)
keeps everything for an account under investigation. The user's mailbox
works as usual, but whatever is removed for good, an emptied Trash, a
deleted folder or a POP3 delete, is first kept out of sight with its
original folder, flags and date. Retention skips held accounts, and purging
one is refused until the hold is lifted. `get-policy` shows how many
messages are held, and

```sh
provision export-held dana@example.com > dana-held.mbox
```

writes them as mbox for review tools, each with an `X-Elemta-Held` header
naming the folder it was deleted from and when.

## Purging a mailbox

Deleting an account keeps its mail. To remove it permanently:

```sh
provision delete-account dana@example.com --confirm dana@example.com --purge
# or, for an account deleted earlier:
provision purge-account dana@example.com --confirm dana@example.com
```

A purge removes the account's folders, messages, filters, delivery records,
two-step and app-password settings, and its class-of-service policy. It is
refused while the directory still has the account, so a live mailbox can't
be emptied by mistake. Message files are deleted by the mailbox's cleanup
once nothing refers to them and the backup grace period
(`body_grace_hours`) has passed, so a restore from a recent backup still
works and mail shared with other mailboxes is kept.

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

Administration uses `[webmail] ldap_url`, `ldap_base`, `ldap_provision_dn` and
`ELEMTA_LDAP_PROVISION_PASSWORD`, together with the existing shared Valkey
session configuration. Older configurations without `ldap_provision_dn` fall
back to `ldap_reset_dn` and `ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD`. The directory bind needs account creation, attribute
updates, password modification and deletion permissions under the mailbox
base, plus access to `ou=mail-addresses` beside it. That subtree reserves
addresses atomically across CLI and dashboard processes. Keep this service
account separate from the read-only LDAP lookup account. The runtime config
and its sidecars must be writable and shared by the CLI, dashboard and SMTP
service. Use LDAPS in production; the shipped plain LDAP setup is dev-only.

The mail schema (`docker/ldap/10-mail-schema.ldif`) gives accounts the
`elemtaMailAccount` class, with aliases, status, quota, forwarding, send-as
rights and a class of service; lists are `groupOfNames` with `elemtaMailList`;
domains are `elemtaMailDomain` entries. [directory.md](directory.md) describes
each attribute and how the directory and the dashboard settings combine.
`scripts/ldap-schema.sh` brings an existing directory up to date and moves
accounts from `extensibleObject`, which older versions used, to
`elemtaMailAccount`. The provisioning service writes only the attributes it
knows rather than accepting arbitrary LDAP attribute writes. Accounts with no
accountStatus are treated as active; missing mailQuotaSize means unlimited.

The mailbox service delivers mail for an alias (`mailAlternateAddress`) to the
account's mailbox, identifies accounts by `entryUUID` so a renamed address
keeps its mail, refuses inactive accounts, and enforces `mailQuotaSize` as a
storage quota in bytes. An external mailbox server needs equivalent mappings.
The SMTP LDAP authenticator applies the same active-status rule.

## LDAP service accounts

Each service binds to the directory with its own account under
`ou=services`, so a leaked credential only grants what that service needs.
No service uses the directory administrator.

| Account | Used by | Access |
|---|---|---|
| `cn=mailbox` | mailbox service logins and delivery lookups | read people and mail addresses |
| `cn=elemta-smtp` | SMTP AUTH and group lookups | read people, mail addresses and groups |
| `cn=webmail` | webmail user lookups | read people, not password hashes |
| `cn=webmail-reset` | password recovery and the reset CLI | read people, write `userPassword` |
| `cn=provisioner` | provisioning CLI and admin console | write people and mail addresses |

Users can still bind and change their own password; anonymous binds see
nothing. `scripts/ldap-service-accounts.sh` creates the accounts, sets their
passwords and installs the matching ACLs. It is idempotent and runs from
`scripts/init-ldap-if-needed.sh`; `make ldap-service-accounts` reruns it.

The dev passwords are random and live in `deployments/compose/.secrets/`
(git-ignored). `make ensure-dev-secrets` creates them once and every install
target depends on it. Compose loads each service's file with `env_file`, and
the Kubernetes dev overlay builds Secrets from the same files. The
environment variables are `ELEMTA_MAILBOX_LDAP_PASSWORD`,
`ELEMTA_AUTH_DATASOURCE_PASS`, `ELEMTA_WEBMAIL_LDAP_SEARCH_PASSWORD`,
`ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD` and `ELEMTA_LDAP_PROVISION_PASSWORD`.

In production, create equivalent accounts in your directory, grant them the
same scopes and supply their passwords from your secret store.

## Admin API and permissions

`/api/provision/status`, `/accounts`, `/accounts/{address}`, the account
`/password`, `/aliases` and `/policy` actions, `/purge`, `/domains` with
their `/class` and `/catch-all`, `/domain-aliases`, `/classes` and `/lists`
back the console. The console has tabs for accounts, delivery aliases,
distribution lists, classes of service and domains. An account's dialog
sets its class and overrides, and shows every setting in effect with the
layer it came from. Deleting an account offers to purge its mailbox too.
The list, class and routing tabs appear when the mailbox admin API is
configured (`ELEMTA_MAILBOX_ADMIN_TOKEN` on the web service). These
routes require dashboard authentication and `system:admin` or
`mail:domain-admin` (see below), including reads. They remain closed when
dashboard authentication is disabled. Mutations require JSON and existing
same-origin write protection.

## Domain administrators

A dashboard user with the `domain-admin` role manages the mail of the
domains assigned to them, and nothing else:

```sh
elemta user add support-lead --role domain-admin --domains example.com,example.org
elemta user role support-lead domain-admin --domains example.com
```

or on the dashboard's Users page, which asks for the domains when you pick the
role (click the domains to change them). The domains are stored with the role
(`domain-admin,domain:example.com` in the users file), so a change applies to
the next request; a domain administrator with no domains can do nothing.

Within their domains they can create, change, disable, delete and purge
accounts, reset passwords, manage delivery aliases, distribution lists and the
catch-all, assign classes of service to accounts, and read the audit log.
They can't:

* see or change anything outside their domains (other domains' accounts are
  neither listed nor reachable, and an alias or list must be in their domains
  too);
* create or edit classes of service, set a domain's default class, add or
  remove domains or alias domains;
* change an account's per-setting overrides (they keep what a system
  administrator set), or change the class of an account on legal hold;
* use the rest of the dashboard: queues, logs, tracing, statistics and
  settings need `api:read`, which the role doesn't have. The dashboard opens
  straight to Mail Administration for them.

## Audit log

Every administrative change is recorded in the mailbox service's database
(the `mailbox_audit` table), whether it was made in the dashboard, with
`elemta provision`, or by `elemta migrate accounts`: who made it, from which
address, what they did, to what, and a short detail such as the new quota,
class or alias. Changes to dashboard users (added, role or domains changed,
password set, removed) are recorded too. Passwords and recovery tokens never
are; CLI arguments are recorded, which is safe because passwords are never
arguments.

The console's Audit log tab shows the newest entries first, with a search
over who, what and target, and "Show more" for older ones. A domain
administrator sees their domains' entries only. The same data is at
`GET /api/provision/audit?actor=&target=&action=&before=&limit=` and on the
mailbox admin API at `/v1/admin/audit`. Entries are never edited or deleted
through any API; prune the table with SQL if you need to.

The log needs the mailbox admin API (`ELEMTA_MAILBOX_ADMIN_TOKEN`). Without it,
changes are still written to the service log (`Mailbox administration`), and
a CLI change that couldn't be recorded prints a warning.

Verification includes service validation and configuration-lock tests, admin
API permissions and lifecycle tests, CLI output/alias tests, SMTP cache tests,
and real LDAP/IMAP/SMTP checks against the development stack.
