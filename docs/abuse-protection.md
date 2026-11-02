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
  Each protocol can have its own pair under **Per protocol** in the settings, for
  example a few connections for POP3 and more for IMAP. Each protocol is counted
  separately.
- **A whole network adds up.** 200 failures across a /24 or /48 block all of it,
  for attackers spread across a rented block.
- **An IPv6 client counts as its /64,** since one network holds all of it.

## What it deliberately doesn't do

- **Accounts are never blocked.** That would let anyone lock a user out by
  guessing wrong. Many addresses guessing at one account shield it instead (see
  "Accounts under attack" below), which leaves its owner able to sign in.
- **Port 25 stays open.** A block for guessing passwords shouldn't lose mail
  from every server sharing that address.
- **It can't absorb a flood.** Traffic that fills the network link has to be
  stopped upstream, by the host or a filtering service.

## Exempt addresses

An inbound allow rule on an address or network, for all protocols, means it's never
limited or blocked, and loopback is always exempt. Add one for your own address,
monitoring and trusted relays. An allow rule that names protocols only lets the
address through on those, and doesn't exempt it from limits elsewhere. Private
networks aren't exempt: on a shared network or behind a NAT they are ordinary
clients. `scripts/cloud-deploy.sh` starts with an allow rule for
`ELEMTA_ADMIN_ALLOWED_IP`.

There used to be a separate allowlist. When the console starts it turns each entry
into an allow rule, noted "From the allowlist", and saves the file without it.

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
| `elemta_abuse_failed_logins_total` | `service`, `source` (`imap`, `pop3`, `sieve`, `smtp`, `webmail`, `admin`) |
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

Try it in log mode first, and check your allow rules before applying. The firewall
has its own copy of the exempt addresses and accepts them first. It covers
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

## Volume limits

Each is off at 0, and they apply in the same modes as everything else: log mode
counts and records without refusing.

- **Messages per hour from one outside address.** Past it, mail is deferred with a
  4xx, so a real mail server tries again later. It covers port 25, because it limits
  volume rather than punishing a mistake. Signed-in users and allowed relays aren't
  counted: their mail is your own.
- **Messages per hour claiming one sender domain.** Past it, that domain's mail from
  outside is deferred the same way. This catches a run forging one domain from many
  addresses, each under the limit above. Large providers send a lot of real mail
  under one domain, so set it well above what you receive from them, or leave it off.
  Bounces, which have no sender, aren't counted.
- **Recipients outside the server per hour, per account.** Past it, the account's mail
  to outside addresses is put on hold until an administrator releases it under
  **Accounts on hold**. A hold doesn't expire, because a taken-over account would
  resume where it stopped. Mail inside the server still flows. Releasing starts the
  count again. Change the password first if the account was taken over.
- **Different accounts one address may fail against.** One password tried on many
  accounts, once each, stays below the failure limit; the number of accounts gives it
  away, and the address is blocked like any other.

Class-of-service sending limits (`messages_per_hour`, `recipients_per_day`) still
apply on top, per class. Those are a quota; the hold is an alarm.

## Accounts under attack

When 20 different addresses (the default for new installs) fail to sign in to one
account within the window, the account is shielded until the attack stops for one
window:

- Its password works only from networks (/24, or /48 for IPv6) it has signed in from
  in the last 90 days. From anywhere else, a right password gets exactly the answer a
  wrong one does, so a guess that happens to be right gets the attacker nothing.
- App passwords and passkeys work from anywhere, since they're too random to guess.
  The account is never locked, and its owner at home or work carries on.
- An account with no sign-ins on record is never shielded, since there's nothing to
  compare against. Networks are only recorded while the setting is on, so turn it on
  before you need it.
- It applies to IMAP, POP3, ManageSieve, SMTP submission and webmail, not to the admin
  console. An alert, *Under attack*, appears under **Unusual sign-ins**.

Someone travelling during an attack can't sign in with the account password until it
ends: give them an app password or a passkey. Existing configurations have it off
(`addresses_per_account = 0`) until set.

## Unusual sign-ins

A stolen password works, so nothing above notices it being used. The Abuse page
lists successful sign-ins that look wrong for their account:

- **Impossible travel:** faster than 1,000 km/h from the account's last sign-in, and
  over 500 km, so a free database guessing a neighbouring city doesn't count.
- **New country:** a country the account hasn't signed in from in 90 days. The first
  sign-in an account ever makes sets its baseline and raises nothing.

They alert and never block: VPNs, mobile networks and satellite links all look like
travel. One account raises each kind at most once an hour. If an alert isn't the
account's owner, change the password and reset two-step sign-in under Mail
Administration. **Block address** blocks where the sign-in came from for 24 hours on
every client protocol, like a manual block. Dismiss alerts you've dealt with.

Every service reports sign-ins from public addresses to Valkey; the admin console
places them with [DB-IP](https://db-ip.com)'s free City Lite database (CC BY 4.0,
attribution on the page) and keeps the last location of each account for 30 days and
its countries for 90. `scripts/cloud-deploy.sh` fetches the database when it's missing
or a month old; set `GEOIP_DOWNLOAD=false` in `cloud.env` to skip it. Elsewhere, point
`ELEMTA_GEOIP_DB` at the `.mmdb` file in the console's container. Turning the alerts off
in the settings stops anything new being kept.

## Allow and deny rules

The Abuse page's rule list holds your own decisions. A change reaches every service
within seconds, with no restart.

| Rule on | Inbound | Outbound |
|---|---|---|
| Address or network | The client connecting, on the protocols you pick | The mail server delivery connects to |
| Domain, subdomains included | Mail from that sender | Mail to that recipient |
| Mail address | Mail from that sender | Mail to that recipient |

- **Allow beats deny**, so one host can be let through a denied network. An inbound
  allow on an address or network for all protocols also exempts it from limits and
  blocks. Allow rules never skip virus or spam scanning.
- **Port 25 follows the rules.** Automatic blocks leave port 25 open, so that a guessed
  password can't cost you mail, but a deny rule is your own decision and applies there.
  Choose protocols to leave SMTP out.
- **Signed-in users** aren't checked against inbound sender rules, because their mail
  is leaving. Outbound rules apply to them and to forwarding. Mail an account would
  forward to a denied address is kept in its inbox instead.
- **Delivery to a denied mail server** bounces at once, with `550 5.7.1`, when every
  mail server for the domain is denied. If only some are and another is merely down,
  the message waits for that one, as it would without the rule.
- **The console refuses a rule that would block the address you're using.**
- **Log mode** counts what rules would refuse and refuses nothing. **Off** ignores them.
- **If Valkey is down** when a service starts, it has no rules until Valkey returns.
  Services already running keep the rules they have.

The older `[access_control]` lists move into rules when the console starts, as
inbound rules: addresses on SMTP only, as they always were, and sender domains. The
console then empties the lists in the file. They stay where they are when Valkey
isn't configured, since the MTA then has no rules to take their place, or when an
entry can't be a rule (the console logs which).
