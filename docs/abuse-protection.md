# Abuse protection

Elemta counts failed sign-ins and limits connections across every service, so
an attacker can't move to another protocol or replica and start again. It is
managed on the **Abuse** page of the admin console, and changes apply within a
few seconds with no restart.

## What it does

- **Failed sign-ins add up** per address across SMTP, IMAP, POP3, ManageSieve,
  webmail, DAV and the admin console. Over the limit, the address is blocked on
  all of them, and clients are dropped at connect, before TLS or a password
  check. The default is 50 failures in 15 minutes.
- **Repeat offenders stay out longer.** The first block lasts 15 minutes, and
  each repeat within a week lasts four times longer, up to 24 hours.
- **One address can't exhaust a service.** It may hold 25 connections to each
  SMTP or mailbox server, and open 120 a minute, which catches clients that
  connect and disconnect too fast to ever hold one. Port 25 isn't rate limited.
- **A whole network adds up.** 200 failures across a /24 or /48 block all of it,
  for attackers spread across a rented block.
- **An IPv6 client counts as its /64,** since one network holds all of it.

## What it deliberately doesn't do

- **Accounts are never blocked.** That would let anyone lock a user out by
  guessing wrong, so accounts are only counted, under *Accounts under attack*.
  Many addresses guessing at one account are therefore shown, not stopped.
- **Port 25 stays open.** A block for guessing passwords shouldn't lose mail
  from every server sharing that address.
- **It can't absorb a flood.** Traffic that fills the network link has to be
  stopped upstream, by the host or a filtering service.

## Allowlist

Addresses and networks on the allowlist are never limited or blocked, and loopback
is always exempt. Add your own address, monitoring and trusted relays. Private
networks aren't exempt: on a shared network or behind a NAT they are ordinary
clients. `scripts/cloud-deploy.sh` starts the list with
`ELEMTA_ADMIN_ALLOWED_IP`.

## Modes

**Enforce** blocks. **Log only** records what would have been blocked under
*History* and blocks nothing, which is the way to try stricter limits. **Off**
stops counting, and connection limits fall back to
`[resources] max_connections_per_ip`.

## Graphs and metrics

The page graphs failed sign-ins by service and refusals by reason over the last
hour, day or week, with a table behind each graph, and lists the addresses with
the most failures. Counts come from every service, kept in Valkey for a week.
With Valkey away the page shows only the console's own counts.

Each service also counts for Prometheus on its metrics endpoint:

| Metric | Labels |
|---|---|
| `elemta_abuse_failed_logins_total` | `service`, `source` |
| `elemta_abuse_refused_total` | `service`, `reason` (`blocked`, `limit`, `rate`) |
| `elemta_abuse_blocks_total` | `service` |
| `elemta_abuse_blocks_active` | `service` |

## Firewall

Services refuse blocked addresses themselves, which still means accepting each
connection. The host firewall can drop them first. `scripts/cloud-deploy.sh`
installs `elemta-abuse-firewall.timer`, which runs `scripts/abuse-firewall.sh` as
root every 15 seconds, and the **Firewall** setting decides what it does:

- **Log only**, the default, reports how many entries it would hold.
- **Apply** drops blocked addresses, in the nftables table `inet elemta_abuse`.
- **Off** removes that table.

Try it in log mode first, and check the allowlist before applying. The firewall
has its own copy of the allowlist and accepts those addresses first. It covers
ports 80, 110, 143, 443, 587, 993 and 8025, never port 25, and only traffic
arriving on the public interface. The page shows each agent's state, entries and
packets dropped, and says when one stops reporting.

The plan comes from a container and the script runs as root, so it checks every
line itself and leaves the firewall alone if anything is wrong. Entries carry the
block's own expiry, so they lapse even if the agent stops. To remove everything
by hand: `nft delete table inet elemta_abuse`.

On Kubernetes behind a load balancer nodes don't see client addresses, so this
firewall doesn't apply there. Services still refuse blocked addresses.

## Where it runs

The services share counts, blocks and the policy through Valkey, at `VALKEY_ADDR`.
The policy itself is saved in `[abuse]` of the runtime configuration, so it
outlasts Valkey, and the admin console publishes it from there.

If Valkey is unreachable nobody is locked out. Each service keeps the last policy
and blocks it has, and counts on its own until Valkey returns.

Connection limits count per service instance, so three replicas allow an address
three times the limit. Failed sign-ins count across all of them. Behind a load
balancer the services need the client's real address: on Kubernetes that is the
PROXY protocol, as `deployments/kubernetes/production/` sets up.
