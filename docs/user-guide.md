# User guide

This guide is for people with a mailbox on an Elemta server. It covers the
webmail, setting up mail and calendar apps, and keeping your account secure.
Your server's name and the exact settings for your account are always under
**Settings → Mail apps and sync** in the webmail.

## Webmail

Sign in at your server's address with your full email address and password.

- **Mail:** the folder list is on the left. Messages can be grouped into
  conversations (Settings → General). Press `?` for keyboard shortcuts.
- **Search:** the box at the top searches the current folder. It also takes
  `from:`, `subject:`, `is:unread` and `has:attachment`.
- **Calendar, Contacts and Tasks:** in the top bar. An invitation sent to you
  shows Yes, Maybe and No, and your answer goes back to the organiser.
- **Settings:** the gear icon, top right. Each section is in the settings
  sidebar:

| Section | What's there |
|---|---|
| General | Your name, reply-to address, signature, theme, time zone, list and calendar options |
| Account | Change your password, set a recovery email |
| Security | Two-step verification and app passwords |
| Mail apps and sync | Settings for mail, calendar and contacts apps, exports |
| Filters and out-of-office | Rules that sort incoming mail, and automatic replies |
| Folders | Create, rename and delete folders |

## Mail apps

Thunderbird, and other apps that support automatic setup, need only your email
address and password. For other apps, enter these settings, replacing
`mail.example.com` with the server shown under Settings → Mail apps and sync:

| Protocol | Server | Port | Security |
|---|---|---|---|
| IMAP (recommended) | `mail.example.com` | 993 | SSL/TLS |
| IMAP | `mail.example.com` | 143 | STARTTLS |
| POP3 | `mail.example.com` | 110 | STARTTLS |
| SMTP (sending) | `mail.example.com` | 587 | STARTTLS, password required |

Your user name is your full email address. Use IMAP unless you have a reason
not to. It keeps every device in step. POP3 downloads mail to one device; when
that app deletes a message, it is deleted from the server too.

## Calendar and contacts on your phone

Calendar, tasks and contacts sync over CalDAV and CardDAV:

- **Android:** use [DAVx⁵](https://www.davx5.com/).
- **iPhone and iPad:** add an account under Settings → Calendar → Accounts and
  choose Other → CalDAV, then Contacts → Accounts → Other → CardDAV.
- **Thunderbird:** add a calendar or address book "on the network".

Use the server address shown under Settings → Mail apps and sync, your email
address and your password. If your account requires app passwords, use an app
password.

## Two-step verification

With two-step verification on, signing in to the webmail needs a 6-digit code
from an authenticator app on your phone as well as your password. A stolen
password alone no longer opens your mail.

1. Install an authenticator app, such as Aegis, 2FAS, Google Authenticator or
   1Password.
2. Go to **Settings → Security** and choose **Set up two-step verification**.
3. Scan the QR code with the app, or type in the key shown under it.
4. Enter the 6-digit code the app shows, and choose **Turn on**.
5. **Save the ten recovery codes** that appear, somewhere away from your phone.
   They are shown only once.

When you sign in, after your password, enter the current code from the app.
Codes change every 30 seconds, and each one works only once.

**Lost your phone?** Enter one of your recovery codes instead of a code. Each
recovery code works once. Then turn two-step verification off and on again with
your new phone to get a fresh set. If you have lost both the phone and the
recovery codes, ask your administrator to turn two-step verification off for
your account.

## App passwords

An app password is a separate password for one mail, calendar or contacts app.
App passwords are random, so they can't be guessed. Each one can be deleted on
its own, which signs out only that app, without changing your account
password.

1. Go to **Settings → Security → App passwords**.
2. Type a name, such as "Thunderbird on laptop", and choose **Create app
   password**.
3. Enter the password shown into the app in place of your account password. It
   is shown only once. If you lose it, delete it and create another.

The list shows when each app password was last used. Delete any you don't
recognise, or for devices you no longer have.

**Require app passwords for mail apps.** With this on, IMAP, POP3 and calendar
and contacts sync refuse your account password, which then works only in the
webmail. Turn it on if you use two-step verification. Otherwise someone with
your password could still read your mail through a mail app. Create app
passwords for your apps before turning it on, or they will stop connecting.

App passwords can't sign in to the webmail. The webmail always needs your
account password, and your code if two-step verification is on.

## Filters and out-of-office

Under **Settings → Filters and out-of-office**:

- **Out-of-office reply:** an automatic answer, optionally between two dates.
  Each sender gets it once every few days, and mailing lists and automated mail
  never get one.
- **Filters:** rules that match incoming mail by sender, recipient, subject,
  body, size or any header. They can move or copy it to a folder, mark it read,
  flag or tag it, forward it, delete it, or reject it. Filters run on the
  server, so they work even when no app is open.

## Passwords

Change your password under **Settings → Account**. Mail apps that use your
account password will ask for the new one; app passwords keep working.

Set a **recovery email** on the same page, an address outside this mailbox, so
you can reset a forgotten password with **Forgot password?** on the sign-in
page. Resetting your password doesn't turn off two-step verification.
