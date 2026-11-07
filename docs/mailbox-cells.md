# Mailbox cells: past one database

[Running more than one of everything](scaling.md) puts several mailbox
servers in front of one Postgres. That scales the servers, not the database:
every mailbox's rows, every write and every restore still go through one
Postgres. Somewhere past a few hundred thousand mailboxes that database is the
limit, and a restore of it takes longer than anyone wants to wait.

Cells split mailboxes across complete, independent mailbox services. Each cell
has its own mailbox servers, its own Postgres and its own body storage, sized to
what one database does well. Nothing in a cell depends on another, so one
cell's outage or restore touches only its own mailboxes, and growing means
adding a cell. A router in front makes the cells look like one mailbox service
to mail apps, the webmail, the MTA and the admin console.

```
  mail apps   webmail   MTA (LMTP)   admin console
        \        |         |          /
         +-------+---------+---------+
         |  elemta mailbox-router    |   any number; keeps no state
         +--+--------------------+---+
            |                    |
   cell a: mailbox servers   cell b: mailbox servers
           Postgres a                 Postgres b
           bodies a                   bodies b
```

A single deployment needs none of this. One cell is the ordinary mailbox
service, and everything below is optional until one database is the limit.

## Where a mailbox lives

Placement is in the directory: the `elemtaMailboxCell` attribute, on a
domain's entry or an account's, through the auxiliary class
`elemtaMailboxPlacement`. `scripts/ldap-schema.sh` adds the attribute and class
to an existing directory on the next deploy.

- **A domain** is placed as a whole. Its mailboxes belong together, because
  shared folders, calendar sharing and free/busy, resources, lists, and the
  domain's policy and routes all work within a domain. None of that reaches
  across cells.
- **An account** may carry its own `elemtaMailboxCell`, which overrides its
  domain's. That is how one mailbox is moved, and how a domain too large for
  one cell is spread over several. The cost is that sharing between that
  domain's cells doesn't work.
- **An alias domain** follows the domain it stands for.
- **Anything without a placement** is in the default cell.

```ldif
dn: elemtaDomainName=example.com,ou=domains,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: elemtaMailboxPlacement
-
add: elemtaMailboxCell
elemtaMailboxCell: b
```

Placements are cached for `[auth] cache_seconds` (30 by default) in routers
and mailbox servers.

## The router

`elemta mailbox-router --config mailbox-router.toml` runs it.
[`config/mailbox-router.toml`](../config/mailbox-router.toml) is a commented
example. It listens wherever a mailbox server would, and works per protocol:

- **IMAP, POP3 and ManageSieve.** The router handles the connection up to
  sign-in: capabilities, STARTTLS, LOGIN, AUTHENTICATE PLAIN, and POP3
  USER/PASS. It then finds the mailbox's cell, connects to one of that cell's
  servers, signs in there with the same credentials, and from then on only
  copies bytes. The cell checks the password and applies its policy and limits.
  The router never checks a password and keeps no state, so routers scale
  sideways and can be replaced freely.
- **Toward a cell, the router behaves as a load balancer.** It sends a PROXY v2
  header with the client's own address, then connects over TLS to the cell's
  public listeners. The cell's sign-in limits, alerts and logs see the client,
  and passwords never cross the network in the clear. List the routers'
  network in each cell's `[server] proxy_protocol_from`, and give each
  `[[cell]]` the name on its certificate (`tls_server_name`) and, if the cell
  uses its own CA, `tls_ca_file`.
- **LMTP.** Each recipient goes to its own cell. RCPT is answered with that
  cell's own answer, so the MTA's recipient check still learns whether a
  mailbox exists. After DATA, each recipient gets its cell's reply, in order.
- **The HTTP APIs.** A request about one account goes to that account's cell:
  the webmail's requests (signed in as the user), and admin requests that name
  an account, list or domain. Classes of service are written to every cell. The
  admin console's lists (domains, routes, domain status, lists, resources, the
  audit log, compliance search) are gathered from every cell and merged.
  Compliance hits carry their cell in the ref (`cell:ref`), so fetching one goes
  back to that cell. An export streams each cell's mbox in turn. An internal
  client can name a cell directly with the `X-Elemta-Cell` header.

Each cell's mailbox servers should know which cell they are:

```toml
[cell]
name = "b"
default = false   # true on the default cell
```

With a name set, a server serves only mailboxes placed in its cell (and, on
the default cell, those placed nowhere). Every sign-in, delivery and API call
checks this where it creates or confirms the account. So a router with a stale
placement, during or just after a move, gets a temporary failure that is
retried through the right cell. Without the check, it would create an empty
mailbox in the old cell.

## Moving a mailbox

```sh
elemta mailbox move-account --config mailbox-a.toml --to-config mailbox-b.toml \
    --to-cell b --address someone@example.com --purge
```

The command runs where it can reach both cells' databases and body stores. It
works in this order:

1. **Freeze.** The mailbox becomes read-only in its old cell. Writes in progress
   finish first, and deliveries meanwhile get a temporary failure, so the MTA
   retries them later.
2. **Copy everything as it was.** Folders keep their UIDVALIDITY, next UID and
   MODSEQ, and messages keep their UIDs, flags and modification sequences, so
   mail apps don't download the mailbox again. Also copied: filters, two-step
   settings, passkeys and the sessions signed in with them, app passwords,
   delivery tokens (a retried delivery is still recognised), PGP keys, push
   subscriptions, shares the mailbox grants, held mail and its policy.
   - Bodies are copied through both cells' stores, each applying its own
     compression and encryption, and checked against their checksums.
   - Rows that name an account in another cell, such as a share with someone
     who stays behind, can't come along. They are counted in the report.
3. **Check, then switch.** The copy is counted against the source in the same
   transaction that makes it writable. Then the account is placed in the new
   cell in the directory.
4. **Wait** `--settle` (40 seconds) for routers' caches, then, with `--purge`,
   remove the old copy. Without `--purge` the old copy stays, read-only.

A move that stops part way leaves the new copy read-only, and running the
command again starts over cleanly. The directory account the command binds as
must be able to write `elemtaMailboxCell`.

## Trying it

`scripts/k8s-cells-dev.sh up` builds the images and starts two cells and two
routers on the local k3s cluster
([`deployments/kubernetes/dev/cells`](../deployments/kubernetes/dev/cells)),
then adds test domains and users. The router is published on the host:

| Port | Protocol |
|---|---|
| 21143 | IMAP |
| 21993 | IMAPS |
| 21110 | POP3 |
| 21424 | LMTP |
| 21190 | ManageSieve |
| 21080 | HTTP |

Then:

```sh
go test -tags cells -run TestCellsEndToEnd ./internal/mailbox/   # deliver, sign in, move
scripts/k8s-cells-dev.sh load-policy                                # log-only limits, for load tests
ELEMTA_CELLS_IDLE=10000 go test -tags cells -run TestCellsIdleLoad ./internal/mailbox/
scripts/k8s-cells-dev.sh down
```

## Measured

On one development machine (the numbers are for comparison, not capacity):

**Idle sessions.** IMAP IDLE waits for a Postgres notification instead of
asking once a second.

| Setup | Database load |
|---|---|
| 5,000 idle sessions, before | 5,524 transactions a second |
| 5,000 idle sessions, after | 116 transactions a second, none of them from the idle sessions |
| 10,000 idle sessions through two routers into two cells | no folder queries in 20 seconds; each cell used 12 database connections |

**Directory sign-ins**, against the directory image without TLS. With TLS,
dialling costs more, so pooling gains more.

| Method | Sign-ins a second |
|---|---|
| A new connection each time | 5,329 |
| Pooled connections | 21,291 |
| Pooled and cached | 172,341 |

**Memory**, 10,000 idle sessions through two routers:

- about 120 KB per connection on a router (TLS on both sides, two buffered
  readers, two goroutines);
- about 70 KB per session on a mailbox server.

## Sizing and what is still to do

- **How many mailboxes per cell** has to come from measuring a cell with real
  traffic, including restore time, not from a guess. Start a cell at the size
  whose Postgres you can restore within your recovery target.
- **Router memory** is the next thing to tune at a quarter of a million
  connections: smaller buffers once a session is spliced, and dropping TLS
  toward the cells where the network is already encrypted.
- **Sharing across cells** (shared folders, calendar delegation, free/busy
  between users in different cells) isn't supported. Keep a domain in one cell
  unless it can't fit.
- **Each cell is still one Postgres.** Its high availability, backups and
  restore drills are per cell, as described in
  [mailbox-engine-architecture.md](mailbox-engine-architecture.md).
