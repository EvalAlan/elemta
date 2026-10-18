# Dev Dovecot

Dovecot 2.4 (Debian 13 packages) serving the dev stack's mailboxes:
IMAP on 14143, LMTP on 2424 (Elemta delivers here), ManageSieve on 4190,
users and passwords from the dev LDAP.

## Layout

| Path | Holds |
| --- | --- |
| `/var/mail/<address>/` | The Maildir, its indexes and its full-text index (`fts-flatcurve/`) |
| `/var/mail/home/<address>/` | The user's home: Sieve scripts (`sieve/`, active one linked as `.dovecot.sieve`), vacation and duplicate-delivery state |

Mail and home used to be the same directory. Maildir reads dot-names there as
folders, so Dovecot's own state files appeared as folders or broke delivery.
`entrypoint.sh` moves Sieve scripts from that old layout on start (once) and
removes the state files Dovecot recreates as needed.

## Search

Two kinds of index:

- **Mailbox indexes** (`dovecot.index*`): flags, UIDs, envelopes, sizes and
  MIME structure. Listing, sorting, counts and header searches (from:,
  subject:, is:unread) are answered from them. Dovecot maintains them itself.
- **Full-text index** (fts-flatcurve, Xapian): message bodies and headers,
  so IMAP SEARCH BODY/TEXT, which the webmail sends for words typed in the
  search box, doesn't read every message. Words match whole or by prefix
  ("invoice" finds "invoices"). Substring matching is off, because it made the
  index about four times the size of the mail.

New mail is indexed as it's delivered (`fts_autoindex`). Mail that was there
before the index existed is indexed the first time a folder is searched. On a
big mailbox that first search can time out with partial results, so index
existing mail ahead of time:

```bash
make dovecot-index                      # every user, every folder, in the background
docker exec elemta-dovecot doveadm index -u someone@example.com '*'   # one user, waits
```

Measured on the dev stack, 30,000 messages (185 MB) in one folder:

| | Dovecot 2.3, no FTS | Dovecot 2.4 + flatcurve |
| --- | --- | --- |
| Body/text search | 3,200–3,500 ms | 8–9 ms |
| Header search (from:) | ~300 ms | ~12 ms |
| Webmail search page, end to end | — | 25–40 ms |
| Index build | — | 31 s (~1,000 messages/s) |
| Index size | — | 149 MB (synthetic mail; real mail is usually smaller) |

Without full-text search, body search grows linearly with the mailbox
(~35 s for 300,000 messages). With it, it stays flat.

## Scaling beyond one server

- The full-text index lives beside each mailbox, so it moves, backs up and
  scales with the mail. There is no search service to run.
- Indexing runs in `indexer-worker` processes (`process_limit` in
  `dovecot.conf`), so a backlog doesn't slow IMAP.
- For many Dovecot servers, put users on backends with a Dovecot proxy
  (director-style routing) in front, so each mailbox is always served, and
  indexed, by one backend. Shared storage under several active backends for
  the same user corrupts indexes.
- Solr (`dovecot-solr`) is the alternative when search must be one shared
  cluster. It costs a separate service, and flatcurve doesn't need one.

## Upgrading from the Ubuntu/Dovecot 2.3 image

Existing Maildirs and indexes are read as they are. On first start the
entrypoint moves Sieve scripts into the new homes. Compiled Sieve binaries
from 2.3 are recompiled automatically; Dovecot logs one "different major
version" error for each, which is harmless. Then run `make dovecot-index`.
