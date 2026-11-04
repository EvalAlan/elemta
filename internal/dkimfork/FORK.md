# go-msgauth dkim fork

The `.go` files here are copied from the `dkim` package of
github.com/emersion/go-msgauth at v0.7.0 (MIT, see LICENSE). The verifier uses
this copy; the signer still uses upstream, which this bug doesn't affect.

Changes from upstream:

- `verify.go`: the check that the signature's `i=` identity is in, or under,
  its `d=` domain compares case-insensitively, as RFC 6376 section 3.5 and
  RFC 4343 require. Upstream compares bytes, so Rocket Mortgage's mail
  (`d=rocketmortgage.com`, `i=RocketMortgage@t.RocketMortgage.com`) failed
  with "domain mismatch" (dkim=permerror, and DMARC fail with it) where
  Gmail and others pass it.
- `verify_case_test.go` (new): tests for the above.
- Import paths rewritten to this module.

Upstream's tests are kept and pass. To update, copy the new release's `dkim`
directory over this one, rewrite the import path in `example_test.go` and
reapply the change above unless upstream has fixed it.
