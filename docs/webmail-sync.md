# Calendar and contact sync (CalDAV and CardDAV)

The webmail serves CalDAV and CardDAV. Phones and desktop apps can then sync
the same calendar, task list and address book that users see in the browser.
Clients and webmail read and write the same ObjectStore, so a change made
on either side shows on the other at the next sync. The default backend uses
hidden IMAP folders; an optional [Postgres backend](webmail-object-storage.md)
copies existing objects on first login and keeps subsequent writes in SQL.

## Endpoints

| Path | Contents |
|---|---|
| `/.well-known/caldav`, `/.well-known/carddav` | redirect to `/dav/` (RFC 6764 discovery) |
| `/dav/` | the signed-in user's principal |
| `/dav/calendars/events/` | events (`VEVENT`) |
| `/dav/calendars/tasks/` | tasks (`VTODO`) |
| `/dav/contacts/default/` | contacts (vCard 3.0 and 4.0) |

Paths never contain the user name. The credentials decide whose data a
request reaches, so one user can't address another user's collections.

## Setting up a client

Settings → *Calendar and contacts on other devices* shows each user the
server address. Clients that support discovery only need the site address:

- **DAVx⁵ (Android):** choose *Login with URL and user name*, enter the
  server address, the mailbox address and the mail password.
- **Thunderbird:** add a new calendar and choose *On the network*. Add the
  address book under *Address Book → New CardDAV Address Book*. Use the
  same address and credentials.
- **macOS and iOS:** in *Internet Accounts* or *Settings → Calendar →
  Accounts*, add a CalDAV account and a CardDAV account under *Other*,
  using the server's host name.

## Authentication and limits

Clients sign in with HTTP Basic: the mailbox address and its mail password.
The webmail checks the credentials against IMAP, as the sign-in page does.
Failures count toward the sign-in page's per-IP and per-user limits, so
CalDAV can't be used to guess passwords faster than the login form. A
client's IMAP connection is reused for 5 minutes between requests. A
password change takes effect for sync clients when that connection is
closed.

Basic authentication sends the password with every request. Serve the
webmail over HTTPS in production. The plain-HTTP compose stack is for
development only. When a reverse proxy sits in front of the webmail, route
`/.well-known/caldav`, `/.well-known/carddav` and `/dav/` to it.

## Behaviour notes

- Each object is stored under its `UID`, which is how the webmail finds it.
  When a client names the resource differently, that name is kept with the
  object and survives edits made in the webmail.
- One `UID` can't appear under two resource names (CalDAV
  `no-uid-conflict`). The events collection only takes `VEVENT`, and the
  tasks collection only takes `VTODO`.
- `If-Match` and `If-None-Match` are honoured, so two clients editing the
  same object can't silently overwrite each other.
- Calendars and address books can't be created or deleted over DAV. Each
  user has the three collections above.
- The server doesn't support `sync-collection` (RFC 6578). Clients fall back
  to comparing ETags, which every common client supports.
- A webmail edit merges into the stored object instead of replacing it.
  Properties the webmail doesn't display, such as contact photos, extra
  alarms, repeating tasks and vendor extensions, are kept. A shown field
  that wasn't changed keeps its stored form, such as a structured address,
  a due time or 3.0 vCard syntax. Overrides of single occurrences stay in
  their series. Editing one in the webmail updates it in place, and deleting
  one adds an `EXDATE` to the series.
