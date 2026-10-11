# Elemta on Kubernetes

Two ways in:

- **`dev/`, the development stack on Kubernetes.** It is what
  `make k8s-install-dev*` runs: the same services as the Compose dev stack
  (`make install-dev*`), which remains the default. It is driven by the
  Makefile, not applied by hand.
- **`standalone/`, Elemta on its own** from the published image:
  `kubectl apply -k deployments/kubernetes/standalone`.

Both are built on `base/`, which holds the Elemta pod (the SMTP server and
dashboard as two containers sharing the queue and runtime config), the LMTP
sink, Valkey, and their volumes.

Both target a single-node cluster on a dev box, written for k3s.

## Installing k3s on Arch / CachyOS

The AUR package installs k3s as a single binary with a systemd unit. It
includes containerd, a local-path storage provisioner and a service load
balancer that binds LoadBalancer ports on the host. That last part is what
lets the dev stack keep `localhost:2525` and friends.

```bash
paru -S k3s-bin          # or yay -S k3s-bin

sudo mkdir -p /etc/rancher/k3s
sudo tee /etc/rancher/k3s/config.yaml >/dev/null <<'EOF'
# Traefik would take ports 80 and 443 and the stack does not use it.
disable:
  - traefik
write-kubeconfig-mode: "0600"
# Run pods on Docker, so images built with `docker build` are visible to the
# cluster without an import step (and without sudo on every rebuild). Leave
# this out to use k3s's own containerd; the Makefile then imports images with
# `sudo k3s ctr images import`.
docker: true
EOF

sudo systemctl enable --now k3s
sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config && chmod 600 ~/.kube/config
kubectl get nodes        # Ready after ~20 seconds
```

`sudo pacman -S kubectl` if it is not installed. The official install script
(`curl -sfL https://get.k3s.io | sh -`) works too. It fetches from
`update.k3s.io`, though, and that fails on a machine whose HTTPS is
intercepted (some VPNs' "threat protection" does this).

If a host firewall is on, allow the pod and service networks, or pods cannot
reach each other or DNS:

```bash
sudo ufw allow from 10.42.0.0/16
sudo ufw allow from 10.43.0.0/16
```

## The dev stack

```bash
make k8s-install-dev          # minimal
make k8s-install-dev-full     # + ClamAV, Rspamd, Roundcube
make k8s-install-dev-bench    # + ClamAV, Rspamd, delivery discarded
make k8s-install-dev-postgres # + Postgres as the queue backend
make k8s-help                 # everything else
```

It uses the same host ports as the Compose stack, so run one or the other:
`make down` before a `k8s-install-dev*` (which refuses while Compose is up),
and `make k8s-down` before going back to `make install-dev`.

Each one does the following:

1. Builds `elemta:dev`, `elemta-dovecot:dev` and `elemta-dns:dev` and makes
   them visible to the cluster.
2. Applies the plugin and queue settings to `config/elemta.toml`.
3. Applies the overlay. Anything a previous overlay added and this one does
   not is removed, but volumes are kept.
4. Re-seeds the runtime config.
5. Loads the LDAP users and prints a dashboard login.

| Overlay (`dev/…`) | Adds |
|---|---|
| `minimal` | Elemta, `elemta-dns` (caching DNSSEC resolver), `elemta-ldap`, `elemta-dovecot`, `elemta-valkey`, `elemta-sink` |
| `full` | `elemta-clamav`, `elemta-rspamd`, `elemta-roundcube` |
| `bench` | `elemta-clamav`, `elemta-rspamd` |
| `postgres` | `elemta-postgres` |

Services keep their compose names, so `config/elemta.toml` works unchanged. So
does every other file that says `elemta-ldap` or `elemta-dovecot`.

Host ports are the same as the Compose stack's. On k3s they are LoadBalancer
Services that bind on the host:

| Port | Service |
|---|---|
| 2525 / 2587 | SMTP / submission |
| 8025 | Dashboard and API |
| 9080 | Prometheus metrics (container port 8080) |
| 8026 | Roundcube (full) |
| 11334 | Rspamd web UI (full, bench) |
| 14143 / 4190 | IMAP / ManageSieve |
| 1389 | LDAP |

Day to day:

```bash
make k8s-status | k8s-logs | k8s-logs-elemta
make k8s-rebuild-dev     # after changing Go code: build, load, restart
make k8s-reseed          # take config/elemta.toml again, discarding UI saves
make k8s-sink-up | k8s-sink-down
make k8s-down | k8s-up   # scale to zero and back; volumes kept
make k8s-down-volumes    # delete the namespace and everything in it
make k8s-bench-queue     # bench-queue against this stack
```

### Things that differ from Compose

- **The cluster has its own image store** unless k3s runs on Docker (above).
  `K8S_IMAGE_LOAD` picks how images get there: `auto` (the default) works it
  out from the node, and `docker`, `kind`, `k3s` and `none` force a choice.
- **The resolver has a fixed address,** 10.43.53.53, because pods name a
  resolver by IP. Elemta and Rspamd use it, and it forwards `cluster.local`
  to kube-dns at 10.43.0.10. Both addresses are k3s defaults. On another
  distribution, change them in `dev/minimal/dns.yaml`,
  `dev/minimal/patches.yaml`, `dev/components/scanners/rspamd.yaml` and
  `deployments/dns/unbound.conf`.
- **The dev certificate** is still `make certs` on the host. It is mounted
  from a Secret where compose bind-mounted it, and regenerated when it lapses.
- **Not on Kubernetes:** the mail-auth lab, ELK, the multinode and monitoring
  overlays, `rspamd-train` and `test-docker`. They stay Compose-only.

## Standalone

```bash
kubectl apply -k deployments/kubernetes/standalone
kubectl -n elemta rollout status deploy/elemta
```

This runs the SMTP server and dashboard, the LMTP sink as the mailbox, and
Valkey, all from `ghcr.io/evalalan/elemta:latest`. Ports are NodePorts so
they don't collide with the dev stack: 30025 (SMTP), 30587 (submission),
30825 (dashboard) and 30080 (metrics).

Its `elemta.toml` turns off what would point at services it does not run:
SMTP AUTH, antivirus, antispam and RBL. `allowed_relays` is empty, so only
loopback may relay. Don't set it to `"private"` behind a Service, where
every client can look like a cluster address.

First login:

```bash
kubectl -n elemta exec -it deploy/elemta -c web -- \
  sh -c 'exec /app/elemta --config /app/runtime-config/elemta.toml user add admin --role admin'
```

To change its config, edit `standalone/elemta.toml` and re-apply. Then take
the template again; the running server reads a seeded copy, which is what the
UI saves to:

```bash
kubectl -n elemta exec deploy/elemta -c smtp -- rm /app/runtime-config/elemta.toml
kubectl -n elemta rollout restart deploy/elemta
```
