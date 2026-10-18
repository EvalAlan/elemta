# go-sieve fork

`interp`, `lexer`, `parser` and `sieve.go` are copied from
github.com/foxcpp/go-sieve at v0.0.0-20260523221512-9ae51b269e52 (MIT, see
LICENSE). Upstream lacks extensions the webmail's filters and common
clients' scripts use.

Changes from upstream:

- `interp/ext_elemta.go` (new): the regex match type, the date
  extension's `date` and `currentdate` tests (RFC 5260), and `vacation`
  (RFC 5230, with RFC 6131 `:seconds`) as an `ActionVacation` the delivery
  agent acts on.
- `interp/load.go`: registers the above and adds `regex`, `mailbox`,
  `date`, `vacation` and `vacation-seconds` to the accepted requires.
- `interp/matchertest.go`, `interp/test_string.go`, `interp/test_body.go`:
  the `:regex` match type.
- `interp/load_action.go`, `interp/action.go`, `interp/applied_action.go`:
  `fileinto :create` (RFC 5490 mailbox extension).
- `interp/runtime.go`: `RuntimeData.Now` and `RuntimeData.Location` for the
  date tests.
- Import paths rewritten to this module.

Upstream's tests are kept and pass. To update, copy the new release over
these directories, rewrite the import paths and reapply the changes above.
