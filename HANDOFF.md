# Elemta — handoff

Written 2026-08-11. Check `git log` for where `main` actually is — a commit hash
written down here is wrong within the day.

This is the context that is **not** derivable from the code or git history: the
traps that cost hours, the reasoning behind decisions that look arbitrary, and
what is genuinely left to do. Everything else, read from the source.

---

## Getting a working stack

```bash
make install-dev-full     # or install-dev for the minimal set
make help                 # targets, variables, and the gotchas below
```

The dashboard requires a login. `make install-dev*` bootstraps an account and
prints the password **once**. If you lose it:

```bash
make reset-admin-password    # creates the account if none exists
```

The account is `admin` at <http://localhost:8025/>; run the target above for the
password rather than looking for it written down. No dev credential is recorded
in this repository on purpose — the stack binds `0.0.0.0`, so a password committed
here is a password on every machine that ever clones it.

The mailbox user (`user@example.com` / `password`, in LDAP) is a **different**
account from the dashboard login. People confuse these.

---

## Traps that will cost you time

**Editing `config/elemta.toml` does not change a running stack.** The services
read a copy on a shared Docker volume, seeded once, because the web UI writes to
it too. `make install-dev*` re-seeds via `ELEMTA_CONFIG_RESEED=true`; plain `up`
and `restart` deliberately do not, or a deploy would discard whatever the
operator saved in the UI. To force it:
`ELEMTA_CONFIG_RESEED=true docker compose -f deployments/compose/docker-compose.yml up -d --force-recreate elemta elemta-web`

**TOML keys land in the wrong table if you are careless.** A key written after a
`[section]` header belongs to that section. This bit me twice: scanner settings
(`reject_on_spam` belongs to `[antispam]`, `address` to `[antispam.rspamd]`) and
`max_connections_per_domain` (top level, *not* `[delivery]`). Both load cleanly
and do nothing. Always parse the file back:
`python3 -c "import tomllib; print(tomllib.load(open('config/elemta.toml','rb')))"`

**Two TOML decoders are in play** — BurntSushi in `internal/smtp`, pelletier in
`internal/config`. Underscored keys do **not** resolve implicitly against field
names in either. Every field needs an explicit `toml:"..."` tag or it is
silently ignored.

**`internal/config` has a reflection tripwire.** `TestToSMTPConfig_AllFieldsMapped`
fails if you add a field to `smtp.Config` and forget to map it. If it complains,
map the field — do not add it to `fieldsIntentionallyUnmapped` without a real
reason. `max_connections_per_domain` sat in that list as "not currently
consumed" while being shown in the UI as a working setting.

**Scanner/policy changes apply without a restart; most other things do not.**
The SMTP server watches the config file and reloads the scanners, allow/deny
lists and blocklists within ~5s (also on `SIGHUP`). Listen address, size limits,
timeouts and the queue backend still need a restart, and the reload log says so
every time. The API reports this as `applies_on_reload` vs `requires_restart`.

**The dev stack delivers over LMTP**, so the outbound SMTP path — including
traffic shaping — does not engage there. Test that path with Go tests, not by
watching the stack.

**Test servers bind `[::]`**, so a probe connecting to `server.Addr()` arrives
over IPv6 loopback. Tests that pin an IPv4-derived string (an RBL query name,
for instance) will fail confusingly. `internal/smtp/rbl_test.go` shows the way
round it.

**The dashboard users file is read at startup only.** `elemta user add` succeeds
and the new account cannot log in until `elemta-web` restarts. The CLI says so
now; the bootstrap target restarts for you.

**ARC is implemented in-tree, and that was deliberate.** `internal/arc` is a
first-party RFC 8617 implementation. The only Go ARC libraries in existence had
0 and 1 GitHub stars respectively, and code that decides whether a message is
authentic is not a place to take an unvetted dependency. The consequence is that
its correctness is our problem, so before changing anything in there, run:

```bash
python3 scripts/dev/arc_crossvalidate.py     # needs a venv with dkimpy
```

It checks both directions against dkimpy — we verify what they seal, they verify
what we seal, and both verify a mixed two-hop chain. Testing our signer against
only our own verifier proves the two agree, not that either is right: a
canonicalization mistake made consistently in both directions passes every
self-round-trip test. That script has already caught one real bug in itself
(dkimpy's `arc_sign` returns `[]` rather than raising when it cannot sign, which
silently made three checks pass against an unsealed message), so trust its
guards, not its green output alone.

**Delivery mode is one global switch, and the modes live in one list.** A server
delivers over `lmtp`, over `smtp`, or `split` — which routes by recipient domain,
local domains to the mailbox server and everything else out. There is no
per-domain transport map beyond that. The valid modes are `smtp.DeliveryModes`
and the config validator reads it; they used to be two lists that disagreed in
both directions, so `local` passed validation then failed at startup and `split`
was rejected before the runtime that implemented it ever saw it.

**Routing is not authorization.** The session decides at RCPT time whether a
recipient may be accepted at all. Split delivery only decides where already
accepted mail goes. Keep those apart — a router that starts deciding who may
send is one bug away from being an open relay.

**Per-destination counters live in Valkey, never Prometheus.** Mail goes to an
unbounded set of domains and an unbounded Prometheus label is how a metrics
endpoint becomes the outage. Anything written per destination needs a TTL that
each write refreshes, and the set naming them needs pruning; the first version
of that report had neither and grew forever.

**`internal/metrics` tests need a real Valkey** and skip without one
(`ELEMTA_TEST_VALKEY` overrides the address). There is no honest way to assert
that a TTL was set or a set was pruned against a fake, and that package went a
long time with no tests at all while both sides of the feature stubbed around it.

**Most of `[logging]` does nothing.** Only `level` is read. The server always
writes line-delimited JSON to stdout and to `/app/logs/elemta.log`; `type`,
`output` and `file` are parsed into the config struct and ignored, and it warns
at startup when they are set. The shipped config used to say `type = "elastic"`
with an Elasticsearch URL, so an operator had every reason to think logs were
being shipped when nothing was.

Do not fix that by wiring up `internal/logging/elastic.go`. It flushes
synchronously while holding its own lock, so a slow log store would stall SMTP
sessions every time the buffer filled; it refuses to construct when
Elasticsearch is unreachable, so the mail server would not start; and it drops
logs silently when disconnected. Mail delivery should not depend on a log store.
`make elk-up` ships the same logs with a Filebeat that reads the log volume, so
Elasticsearch being down costs you logs and nothing else.

**A red Elasticsearch on a dev box is nearly always disk.** Elasticsearch will
not allocate a shard to a node past its 90% high watermark, and the symptom is
not "disk full": the stack comes up healthy, Kibana loads, and the only sign is
bulk-insert timeouts in Filebeat's log. This was measured, not assumed — at 92%
used with 77GB free, which is not a machine in trouble, the default watermark
left the cluster red with four unassigned shards and nothing indexed; the same
disk with the watermark off gave a yellow cluster and 18,860 events. The dev
overlay disables it for that reason. If you are debugging a red cluster
anyway, `docker system df` is usually the answer and build cache is normally
most of it.

**Querying Spamhaus through a public resolver returns `127.255.255.254`** — a
status code about *you*, not about the sender. Treating any `127.0.0.0/8` answer
as a listing refuses all mail. `internal/smtp/rbl.go` only accepts
`127.0.0.0/24` and logs the rest loudly. Do not "simplify" that.

---

## What CI checks that local `go test` does not

- **gosec** (blocks on MEDIUM+). It flagged SQL string concatenation in the
  suppression store; the fix was writing both queries out, not annotating.
- **staticcheck** via golangci-lint. Catches unused methods, redundant nil
  checks, and inconsistent receiver names.
- **`gofmt -l .` as a separate step.** golangci-lint does *not* run it, so a
  clean `golangci-lint run` is not enough — this has already cost one CI round
  trip. Run `gofmt -l .` over the whole repo before pushing.
- **`go mod tidy -diff`.** Adding a dependency with `go get` leaves it marked
  `// indirect`; tidy before pushing.
- `golangci-lint run ./...` and `gosec -severity medium ./...` locally will save
  a round trip.

One known oddity: on PR #126 the `CodeQL` aggregate check failed with
*"1 configuration not found"* while the substantive `CodeQL Analysis` passed.
The same code went green on #127 and #128, so it appears environmental — but if
you see it again, check before assuming.

---

## Recently landed, with the reasoning worth preserving

| PR | What | The non-obvious part |
|---|---|---|
| #126 | Suppression list + bounce classification | Only failures *about the recipient* suppress. "Mailbox full", "message too large", "blocked", and unrecognised 5xx do **not** — suppressing those deletes valid addresses because our IP was blocked, and nobody notices they stopped receiving mail. |
| #127 | Per-destination traffic shaping | A backed-off destination **refuses immediately** rather than sleeping. Holding a worker until Gmail is ready stalls every other domain behind it. |
| #128 | Inbound SPF/DKIM/DMARC | Enforcement is off by default: the first thing DMARC enforcement does on a real server is reject forwarders and mailing lists, which break SPF alignment by design. Every inconclusive result resolves towards accepting. |
| #120 | Config reload | Component objects swap for the *next* session; live sessions keep the policy they started under, so a message is never half-scanned by two policies. |
| #121 | Message tracing | A message has two IDs (session and queue). Only the reception record carries both — that link is what makes a trace whole. |
| #123 | Mandatory login | Was wide open: "Guest" was full admin access with a friendlier name. |
| #131 | SPF/DKIM/DMARC as independent plugins | A file carrying both legacy `[inbound_auth]` and new `[plugins.*]` tables is rejected rather than resolved to one of them. A config that means two things should not start a mail server. |
| — | First-party ARC | Fails **closed**, unlike SPF and DMARC. An inconclusive SPF result says little; an ARC chain that cannot be verified is damaged or forged, and honouring it defeats the point. |
| #135 | Campaign recipients from the directory | Imported into the compose box, not stored as "everyone". A campaign that expands at send time mails a different set than the one that was reviewed. Disabled accounts are never imported. |
| #137 | Split delivery | A message to both a local mailbox and an outside address is delivered twice and the per-recipient outcomes merged. The queue drops delivered recipients before retrying, so without that a remote deferral redelivers locally on every attempt. |
| #138 | Delivery method | Six call sites hardcoded `"lmtp"`, and the message trace reads that field back — so the feature built to show how mail left the building was wrong about every remote message. |
| #139 | Per-destination report | Counted before the success/failure branch, or a domain deferring half our mail looks perfect. Keyed on the recipient's domain, not the MX host, or one destination splits into rows that each look fine. Bounces are counted but never cause backoff. |

---

## What is actually left

**Salvage two things out of `internal/delivery`, then delete the rest.** That
package holds a complete, tested delivery subsystem that nothing constructs —
`delivery.NewManager` has no caller outside the package. Only `mtasts.go` is
live, used by the SMTP delivery handler. Do not read "unused" as "worthless";
the verdict differs per file:

| | |
|---|---|
| `dns_cache.go` | **Adopt.** Nothing caches MX today: the SMTP handler falls back to `net.DefaultResolver`, so every delivery attempt re-resolves. `internal/queue` already defines an `mxResolver` interface and `DNSCache.LookupMX` has exactly that signature, so it is close to a drop-in. |
| `pool.go` | **Adopt.** The queue dials fresh for every delivery. Connection reuse to large receivers is standard in the MTAs this competes with, and it composes with the shaper's per-domain cap. |
| `tracker.go` | **Drop.** Duplicates the queue's attempts, states and the tracing feature built on them. |
| `router.go`, `manager.go` | **Drop.** The local-versus-relay decision is the split delivery handler's job now. |

Beware of measuring this with `grep -v internal/delivery/` — that hides
intra-package use and makes the router look like orphaned code with no tests. It
has both.

**Feedback loops (ARF).** The suppression list is fed by SMTP-time bounces only.
Yahoo and Microsoft send ARF complaint reports and nothing consumes them, so a
recipient who marks a message as spam keeps receiving mail. This is the real
deliverability gap now that shaping, suppression and per-destination reporting
exist.

**User management in the UI.** `elemta user add` is shell-only. API keys already
have a UI; users do not. Note the read-at-startup wart above — fixing that
properly (re-read on change, like the config reload) would be part of this.

**DKIM key and TLS certificate management.** Certificate *expiry* is reported on
the Health page (#122); nothing manages renewal, and DKIM keys are
config/CLI-only.

**Nobody has driven the dashboard in a browser.** The UI work has been verified
with jsdom harnesses against the shipped `app.js`, by checking the files the
container actually serves, and by reading the API responses. That is real
evidence and it caught real bugs — but the settings-tabs failure was the kind a
person finds in ten seconds and a harness does not.

---

## How this codebase expects to be worked on

- **Comments explain why, not what.** Especially: why a decision went one way
  when the other way looks reasonable. Most of the value in the recent commits
  is in those comments — do not strip them.
- **Verify against the running stack**, not only tests. Most of the real bugs
  this month were found by sending actual mail and reading actual logs: the
  envelope-sender bug, the mismatched TLS key pair, the identifier link, the
  healthcheck. Tests passed throughout.
- **Commit messages and PR bodies carry the reasoning**, including what was
  tried and rejected and what a test caught. They are long on purpose.
- **No AI attribution anywhere** — no co-author trailers, no "generated with"
  footers, in commits or PR bodies. This is a hard rule in this repo.
- Branch per change, PR, wait for CI, squash-merge. Do not merge with a red
  check without saying so plainly.

---

## Quick reference

```bash
# stack
make install-dev-full                 # full dev stack
make status / make logs
docker compose -f deployments/compose/docker-compose.yml restart elemta elemta-web

# after changing Go code, the dev stack needs a rebuild
docker build -t elemta:latest .
ELEMTA_CONFIG_RESEED=true docker compose -f deployments/compose/docker-compose.yml \
  up -d --force-recreate elemta elemta-web

# tests
go test ./internal/...                # internal/smtp takes ~135s
go test -race -run TestReload ./internal/smtp/
golangci-lint run ./... && gosec -severity medium ./...

# poking the running stack
printf 'EHLO probe\r\nMAIL FROM:<a@example.com>\r\nRCPT TO:<demo@example.com>\r\nDATA\r\nSubject: x\r\n\r\nhi\r\n.\r\nQUIT\r\n' \
  | nc localhost 2525
curl -s -c /tmp/c -X POST http://localhost:8025/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"..."}'
curl -s -b /tmp/c http://localhost:8025/api/suppression
```

Ports: SMTP 2525, dashboard 8025, Roundcube 8026, metrics 8080.
