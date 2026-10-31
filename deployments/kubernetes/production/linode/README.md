# Elemta on Linode Kubernetes Engine

The replicated deployment (`../../ha`) with the HTTPS and mail edge
(`../edge`), set up for LKE. This directory is generic: nothing in it names
a real deployment. One deployment's settings, generated config and secrets
live in `instance/`, which git ignores.

| Path | What |
|---|---|
| `component/` | What LKE changes: NodeBalancers with PROXY protocol, the address range trusted for it, the shared storage class, this deployment's names |
| `haproxy-values.yaml` | The HTTPS ingress's NodeBalancer settings, on top of the edge's |
| `template/` | The deployment `make linode-config` generates into `instance/`, and the example `settings.env` |
| `instance/` | Yours, git-ignored: `settings.env`, `secrets/`, and what is generated from them |

## Before you start

- **An LKE cluster** of three or more nodes, and its kubeconfig. Every
  `linode-*` target that touches the cluster needs `LINODE_CONTEXT` set to
  its context, and refuses to run unless that is kubectl's current context,
  so nothing meant for it reaches another cluster.
- **Outbound port 25.** Linode blocks it on new accounts until a support
  ticket lifts it. Without it Elemta receives mail but cannot deliver any.
- **Object Storage**: a bucket and an access key for message bodies.
- **Storage that several nodes can mount** (see Storage).
- `helm`, `kubectl`.

## Steps

```sh
make linode-init                     # instance/: settings, generated secrets
$EDITOR deployments/kubernetes/production/linode/instance/settings.env
#   and replace CHANGE-ME in instance/secrets/s3.env and recovery-smtp.env
make linode-config                   # generate the deployment from settings.env
make linode-check                    # refuses example values and missing secrets

kubectl config use-context <lke-context>
make linode-edge  LINODE_CONTEXT=<lke-context>   # cert-manager, HAProxy, CloudNativePG; once
make linode-check LINODE_CONTEXT=<lke-context>   # also checks the cluster
make linode-apply LINODE_CONTEXT=<lke-context>   # apply; directory accounts
#   point DNS at the NodeBalancers it lists, wait for the certificates
make linode-admin LINODE_CONTEXT=<lke-context>   # the first dashboard login
```

Back up `instance/` somewhere safe. Its secrets exist nowhere else, and
losing them means regenerating every credential.

After changing `settings.env`, `config/elemta.toml` or
`config/mailbox-main.toml`, run `make linode-config` and apply again. The
running services read their settings from the shared runtime volume, which
keeps what was saved in the dashboard; `make k8s-reseed` replaces it with
the newly generated config.

## DNS

`make linode-apply` lists three NodeBalancers:

- `elemta-mail-public` (SMTP 25, submission 587): the address of
  `MAIL_HOST`, which is your domain's MX.
- `elemta-mailbox-public` (IMAPS 993, IMAP 143, POP3 110, Sieve 4190): give
  it a name of its own (for example `imap.`), since it has its own address.
- The HAProxy ingress (80, 443): the address of `ADMIN_HOST` and
  `WEBMAIL_HOST`. Port 80 must reach it for certificate validation,
  including for `MAIL_HOST`.

Deleting a LoadBalancer Service releases its address. To keep the MX
address across that, reserve an IPv4 in Linode and add the
`service.beta.kubernetes.io/linode-loadbalancer-reserved-ipv4` annotation
to `elemta-mail-public` in your instance.

## Client addresses

A NodeBalancer proxies each connection, so Elemta would otherwise see the
NodeBalancer as every client: spam and blocklist checks, relay rules, rate
limits and sign-in throttles all depend on the real address. Every
NodeBalancer here sends the client's address in a PROXY protocol v2 header,
and the MTA, the mailbox service and HAProxy believe the header only from
`PROXY_PROTOCOL_FROM`.

The default, `192.168.255.0/24`, is where NodeBalancers on Linode's private
network connect from. Every customer's NodeBalancers in a data center share
that range, so a NodeBalancer someone else created could reach your nodes
and claim any client address. To close that, run the cluster in a VPC with
the NodeBalancers' backends in it, set aside a range for them
(`service.beta.kubernetes.io/linode-loadbalancer-backend-ipv4-range`), and
set that range as `PROXY_PROTOCOL_FROM` and in `haproxy-values.yaml`. A
Cloud Firewall on the nodes that admits only your NodeBalancers also
works.

## Storage

Postgres, Valkey, the directory and ClamAV use LKE's default block
storage. Linode volumes are at least 10 GB each, so the small claims are
rounded up.

The runtime volume the MTA, dashboard and webmail share (saved settings,
dashboard users, the webmail session key) needs ReadWriteMany, which LKE's
block storage does not provide. Install a class that does, such as
Longhorn or an NFS provisioner, and name it as `RWX_STORAGE_CLASS`.
Longhorn's ReadWriteMany needs NFS client tools on the nodes; check its
current LKE instructions.

## Outbound mail

The MTA delivers straight to each recipient's MX, from whichever node it
runs on. LKE replaces nodes on upgrades and recycles, so that address
changes, and with it reverse DNS, SPF and sending reputation. For mail
that reaches inboxes, send from one fixed address with reverse DNS and SPF
pointing at it. Elemta can't yet hand outbound mail to a relay
(a smarthost), so this is open work. Until then, keep the cluster's node
addresses in SPF and set each node's reverse DNS.

## Known gaps

- **Outbound relay**, above.
- **Webmail's submission hop** to the MTA (port 2588, inside the cluster)
  uses STARTTLS with verification off: the MTA's certificate names
  `MAIL_HOST`, and the webmail has no setting for the name to verify. It is
  encrypted, and the NetworkPolicy admits only webmail pods to that port.
- **Images are amd64 only**, so the nodes must be x86.
