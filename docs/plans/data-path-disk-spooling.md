# Plan: spool message data to disk instead of buffering in memory

Status: **stage 0 done (characterisation tests + header prepend); stages 1-4 not implemented**

## Progress

**Stage 0 — pin the current behaviour.** Done. The round-trip and DKIM tests
the plan called for now exist and pass against the in-memory implementation, so
the refactor has a baseline to preserve:

- `internal/smtp/message_roundtrip_test.go` — byte equality between what a
  client submits and what the queue stores, over dot-stuffing, CRLF, 8-bit
  content, a body line that looks like the terminator, long lines and large
  messages; plus the negative cases (rejected message, client disconnect
  mid-DATA) that will catch orphaned spool files.
- `internal/dkim/body_fidelity_test.go` — signs content shaped like what the
  queue stores and verifies it with a stubbed-DNS verifier, across the body
  shapes most likely to be mangled, with a control proving the check detects
  corruption.

Two findings came out of writing them:

1. **`addServerHeaders` appended rather than prepended.** This hop's `Received`
   was spliced in below the sender's headers, which violates RFC 5321 §4.4
   (the trace record belongs at the top) and reverses the order a multi-hop
   trace is read in. Fixed. It also mattered structurally: appending forced the
   whole message to be parsed and rebuilt in memory, which is precisely what
   makes stage 2 hard. Prepending reduces the header step to writing a prefix
   ahead of untouched bytes, so it becomes `io.MultiReader(headers, spool)`.

2. **DKIM cannot detect a line-ending change.** Relaxed body canonicalisation
   normalises CRLF before hashing, so a spool that altered line endings would
   still produce valid signatures while corrupting the message on the wire.
   DKIM verification is therefore *not* sufficient coverage for this refactor;
   the byte-equality tests are what protect that property.

## Problem

`DataHandler.ReadData` logs "streaming message data reading" but does not
stream. It accumulates the whole message into a `bytes.Buffer`
(`internal/smtp/session_data.go`), and `ProcessMessage` then budgets roughly
three times the message size for processing.

Two consequences follow.

**Maximum message size is bounded by RAM, not by policy.** A session cannot
exceed `PerConnectionMemoryLimit`, which defaults to
`MaxMemoryUsage / MaxConnections` — 1GB/100 ≈ 10.7MB. Until recently the
server advertised `max_size` in EHLO regardless and rejected oversized mail
part-way through DATA; `reconcileMessageSizeLimit` now clamps the advertised
value instead, so the two agree. But the ceiling is still RAM.

**Peak memory scales with concurrent senders.** DATA reception is
network-bound and slow. Every in-flight session holds its entire message
resident for the duration. A hundred slow senders at the configured limit is a
hundred full messages in the heap, and the failure mode is rejecting
legitimate mail with `452`/`552` under load.

Postfix and Exim spool to disk during DATA precisely to break this coupling.

## Why this is not a small change

The message body is passed around as `[]byte` from reception all the way to
delivery. Every one of these has to change together, or the spooling gains
nothing because something downstream loads the whole message anyway:

| Site | Current shape |
| --- | --- |
| `session_data.go: ReadData` | accumulates into `bytes.Buffer` |
| `session_data.go: ProcessMessage` | `data []byte` through validation and scanning |
| `session_data.go: addServerHeaders` | prepends `Received:` by rebuilding the slice |
| `session_data.go: saveMessage` | `queueManager.EnqueueMessage(..., data []byte, ...)` |
| `queue/interfaces.go: StorageBackend` | `StoreContent(id, []byte)`, `RetrieveContent(id) ([]byte, error)` |
| storage backends | file, sqlite, postgres, indexedfs — four implementations |
| `queue/delivery_handler.go` | reads content into memory, then writes to the SMTP `DotWriter` |
| `queue/delivery_handler.go: DKIMSigner` | `Sign(content []byte, domain string) ([]byte, error)` |

The scanners are the one part already in good shape: `antivirus.Manager` and
`antispam` expose `ScanReader` and `ScanFile` alongside `ScanBytes`.

DKIM is the subtle one. Signing needs a hash over the canonicalised body, so
a streaming implementation has to either make two passes over the spool file
or tee the body through the hash while writing. Getting the ordering wrong
relative to `addServerHeaders` produces signatures that verify locally and
fail everywhere else — a failure that is invisible until recipients start
rejecting mail.

## Staged plan

Each stage should land and soak separately. Stage 1 alone does not lift the
size ceiling; it is groundwork, and it is not worth doing unless stages 2 and
3 follow.

### Stage 1 — spool on receive

Introduce a `MessageSpool` that writes to a temp file in the queue directory
(same filesystem as the queue, so the final placement can be a rename rather
than a copy).

- `ReadData` writes each validated, dot-unstuffed line to the spool.
- Keep an in-memory fast path below a threshold (say 256KB) so the common
  small message never touches disk.
- `MessageSpool` exposes `Reader() (io.ReadSeekCloser, error)`, `Size()`, and
  `Path()`.
- Lifecycle is the risk: the spool must be removed on every exit path
  including panics, rejections, timeouts, and `RSET` mid-DATA. Use `defer`
  at the point of creation, and add a startup sweep for orphans.
- Memory accounting changes: the per-connection check applies to the spool's
  byte count, not to heap usage.

> **Where the memory actually goes.** Benchmarking the scan path
> (`BenchmarkSecurityScan`) found the resident copy was not the dominant cost.
> The content scans allocated roughly **fifteen times the message size** per
> delivery, because each lowercased the whole message inside its pattern loop.
> An 8MB message produced ~126MB of garbage and took 331ms. Sharing one
> lowercased copy cut that to ~58MB and 242ms.
>
> The remaining ~7x is `ValidateSMTPParameter("DATA_LINE", body)`, which runs
> Unicode NFC normalisation over the entire message body. That validator is
> named and shaped for a single SMTP line but is handed the whole message, so
> every delivery normalises the full body. Bounding it, or applying it per line
> as the name implies, is the next win — but it changes what a security check
> inspects, so it wants review rather than a drive-by fix.

### Stage 2 — process from the spool

- Header extraction reads only the head of the spool, not the whole message.
- `performSecurityScan` switches to `ScanFile` / `ScanReader`.
- `performContentAnalysis` is the awkward one — it currently does substring
  matching over the whole body. Either bound it to the first N bytes (which
  is what it effectively wants) or make it a streaming matcher.
- `addServerHeaders` stops rebuilding the slice; trailer headers are prepended
  at enqueue time via `io.MultiReader`.

### Stage 3 — stream into and out of the queue

> **Correction.** This stage was described below as additive — new reader-based
> methods alongside the existing `[]byte` ones. That was wrong, and the reason
> is worth writing down before anyone starts.
>
> Enqueue idempotency does not just pass content through; it *compares* it.
> `CreateMessageIfAbsent` decides whether a retry is the same message by
> `bytes.Equal` against the stored content, and `enqueueTombstone` serialises
> **the entire message body into JSON** so a consumed ID can be checked after
> the message is gone. There are a dozen such comparisons across the file and
> sqlite backends.
>
> Streaming therefore requires replacing content equality with a content hash
> everywhere, which changes the on-disk tombstone format. Existing deployments
> have tombstones written in the current shape, so this needs a versioned
> record and a migration, or an upgrade will start reporting "conflicts with
> consumed enqueue identity" and **refuse legitimate mail**.
>
> That makes stage 3 its own reviewed change with its own migration test, not a
> continuation of stage 2. Stages 1 and 2 remove the dominant memory cost
> without touching it.

- Add `StoreContentFromReader(id string, r io.Reader) error` and
  `RetrieveContentReader(id string) (io.ReadCloser, error)` to
  `StorageBackend`, with the existing `[]byte` methods kept as thin wrappers
  so the change is additive.
- `FileStorageBackend` and `indexedfs` become renames of the spool file —
  cheap and atomic. `sqlite` and `postgres` store blobs, so they can only
  stream on the read side; they should keep buffering on write and be
  documented as unsuitable for large `max_size`.
- `delivery_handler` writes from the reader straight into the `DotWriter`.
- DKIM signs from a reader, hashing the body in one pass while writing.

### Stage 4 — decouple the limits

Once nothing holds a whole message, `reconcileMessageSizeLimit` can stop
clamping. `max_size` becomes a policy limit and `PerConnectionMemoryLimit`
goes back to bounding what it should have bounded all along: buffers and
per-session bookkeeping.

## Test strategy

The existing suite will not catch the failures that matter here. It needs:

- A round-trip byte-equality test: submit a message, read what the queue
  stored, assert equality — including CRLF, dot-stuffed lines, 8-bit content,
  and a body containing a lone `.` line.
- A DKIM test that signs a spooled message and verifies the signature with an
  independent verifier, not the signer's own code.
- Failure injection during DATA: client disconnect, deadline, size overrun,
  `RSET` mid-transfer. Assert no orphaned spool files remain.
- A concurrency test showing peak RSS stays flat as concurrent senders
  increase — this is the property the whole change exists for, so it should
  be asserted rather than assumed.
- Crash-recovery: kill the process mid-DATA, restart, assert the orphan sweep
  cleans up and no partial message is enqueued.

## Risk

This is the mail data path. The realistic failure modes are silent body
corruption, broken DKIM signatures, orphaned spool files filling the queue
filesystem, and partially-written messages surviving a crash. None of these
announce themselves in a green test run, which is why the round-trip and
crash-recovery tests above are prerequisites rather than follow-ups.

Recommend implementing behind a config flag (`queue.spool_to_disk`) defaulting
to off, so it can be enabled per-deployment and rolled back without a rebuild.
