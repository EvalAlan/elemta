# Migrating users to Elemta

`elemta migrate` moves users from another mail system: their mail over
IMAP, their calendars, tasks and contacts from `.ics` and `.vcf` exports,
and the accounts, aliases and distribution lists themselves from a CSV.

Everything goes into the mailbox service through its admin API, so no
destination passwords are needed. Run the commands where the dashboard
runs (the web service has `ELEMTA_MAILBOX_ADMIN_TOKEN`), for example:

```sh
docker exec -it elemta-web /app/elemta -c /app/runtime-config/elemta.toml migrate --help
kubectl -n elemta exec -it deploy/elemta -c web -- /app/elemta -c /app/runtime-config/elemta.toml migrate --help
```

Every command can be run again. What was already copied is recognised and
skipped, so an interrupted run is finished by repeating the same command.
That also gives the usual cut-over plan:

1. Create the accounts (`migrate accounts`).
2. Copy everyone's mail while they keep using the old system (`migrate mail`).
   This can take days for large mailboxes; it doesn't matter.
3. Import calendars and contacts (`migrate import-files`).
4. Switch MX (and the webmail and mail-app hostnames) to Elemta.
5. Run `migrate mail` once more. It copies only what arrived since the last
   run, in minutes.

## Accounts, aliases, classes and lists

```sh
elemta migrate accounts --csv accounts.csv
```

```csv
type,address,name,quota,password,aliases,class,members,owner,posting
account,dana@example.com,Dana Jones,5G,,dana.jones@example.com;dj@example.com,staff,,,
account,lee@example.com,Lee Park,2G,,,,,,
list,team@example.com,Team,,,,,dana@example.com;lee@example.com;partner@other.example,dana@example.com,members
```

* Domains must already be local (`provision create-domain`); classes must
  already exist (`provision set-class`).
* An existing account is left alone apart from adding missing aliases and
  setting its class, so the file can be run again after fixing a row.
* An empty password sets a random one nobody knows. The report lists those
  accounts; reset their passwords (`provision set-password`) or let users
  recover them before they sign in. Passwords are never printed.
* Several aliases or members are separated by `;` or `|`. Lists are created
  or replaced; see "Distribution lists" in mail-administration.md.

## Mail

One user, with their source password prompted for (or piped on stdin):

```sh
elemta migrate mail --source imap.old.example:993 --source-user dana --dest dana@example.com
```

Many users from a CSV, four at a time:

```sh
elemta migrate mail --source imap.old.example:993 --users users.csv --parallel 4
```

```csv
dest,source_user,source_password
dana@example.com,dana,her-old-password
lee@example.com,lee@old.example,his-old-password
```

Most mail systems let an administrator sign in on a user's behalf for
migrations (SASL PLAIN with an authorization identity). Then no user
passwords are needed: leave `source_password` out and give
`--source-admin admin@old.example`; the administrator's password is
prompted for or read from stdin.

What is copied:

* Every folder that can hold mail, with read, answered, flagged and draft
  state, user keywords, and each message's original date.
* Sent, Drafts, Trash, Junk and Archive land in the webmail's own folders,
  recognised by the source's special-use flags or by common names ("Sent
  Items", "Deleted Items", "Junk E-mail", "Spam", ...). Other folders keep
  their names and hierarchy.
* Messages the source has marked deleted are left behind.
* Messages over the mailbox's size limit are skipped and counted.

Options: `--source-tls imaps|starttls|none`, `--source-insecure` for a
source with a self-signed certificate, `--exclude 'Notes;Shared Folders'`
to leave folders out, `--state-dir` (default `migrate-state`) for the
progress files, and `--json` for a machine-readable report.

The state directory remembers, per user and folder, the last message
copied, so reruns download only new mail. Keep it between runs. If it is
lost, a rerun lists every message again but still stores nothing twice.
If a source folder is renumbered (its UIDVALIDITY changes), that folder is
copied again from the start, and those copies are duplicates.

Quota applies: a mailbox that fills up stops that user's migration with a
message saying so. Raise the quota (`provision modify-account --quota` or the
class) and run again.

## Calendars, tasks and contacts

Export each user's calendars and address books from the old system as
`.ics` and `.vcf` files (most systems offer this per user, or through
CalDAV/CardDAV with any client), then:

```sh
elemta migrate import-files --dest dana@example.com dana-calendar.ics dana-tasks.ics dana-contacts.vcf
```

Each event (with its recurrence exceptions), task and contact becomes one
entry in the user's Calendar, Tasks or Contacts, visible in the webmail and
to CalDAV/CardDAV clients at once. Entries keep their UIDs, so invitations
already sent still match. Importing the same file again adds nothing; a
later export with changes adds the newer version, which the webmail shows.

This uses the webmail's default IMAP object store. With
`object_store = "postgres"`, import the same files through the user's
CalDAV/CardDAV account instead.

## Checking a migration

Each command prints a summary per user: copied, already there, too large and
failed counts. It exits non-zero if any user or row didn't finish. The
mailbox's admin API logs each refusal. Spot-check a few users in the webmail
before switching MX.
