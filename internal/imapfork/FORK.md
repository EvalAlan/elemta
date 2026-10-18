# go-imap server fork

`imapserver` and the `internal` packages here are copied from
github.com/emersion/go-imap/v2 at v2.0.0-beta.8 (MIT, see LICENSE). The
upstream server has no way to add commands, and the Elemta mailbox service
needs extensions that clients and the webmail depend on.

Changes from upstream:

- `imapserver/extensions.go` (new): SORT and SORT=DISPLAY, THREAD,
  GETQUOTA/GETQUOTAROOT and ID, each advertised only when the session
  implements its interface.
- `imapserver/condstore.go` (new): CONDSTORE and QRESYNC (RFC 7162):
  SELECT/EXAMINE parameters and HIGHESTMODSEQ, FETCH MODSEQ and
  (CHANGEDSINCE n [VANISHED]), STORE (UNCHANGEDSINCE n) with MODIFIED,
  SEARCH MODSEQ, STATUS HIGHESTMODSEQ, ENABLE, and expunges reported as
  VANISHED once QRESYNC is enabled. Hooked into `select.go`, `fetch.go`,
  `store.go`, `status.go`, `search.go` and `enable.go`.
- `imapserver/conn.go`: dispatch for the commands above.
- `imapserver/capability.go`: advertise them.
- `imapserver/message.go`: keyed struct literals, so `go vet` passes.
- Import paths rewritten to this module.

To update: copy the new upstream release over these directories, rewrite
the import paths, and reapply the changes listed here. Upstream style
findings are excluded from lint in `.golangci.yml`.
