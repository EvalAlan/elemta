# Elemta on Kubernetes

A single-node deployment of Elemta for a development cluster (k3s, kind,
minikube, Docker Desktop), applied with kustomize:

```bash
kubectl apply -k deployments/kubernetes
kubectl -n elemta rollout status deploy/elemta
```

## What it deploys

| Resource | What it is |
|---|---|
| `deploy/elemta` | One pod: the SMTP server (`smtp`) and the dashboard (`web`), sharing the queue and runtime config |
| `deploy/elemta-mailbox` | `deployments/sink/lmtp_sink.py`, an LMTP server that accepts mail and discards it |
| `deploy/elemta-valkey` | Valkey for the dashboard's delivery statistics (optional) |
| `pvc/elemta-queue` | The mail queue (5Gi) |
| `pvc/elemta-runtime-config` | The live config, the development certificate and the dashboard users file |

Ports, as NodePorts so they are reachable on the node without a load balancer
(on a single-node k3s that is `localhost`):

| Node port | Service |
|---|---|
| 30025 | SMTP (MX), container port 2525 |
| 30587 | Submission, container port 2587 |
| 30825 | Dashboard and API, container port 8025 |
| (ClusterIP) | Prometheus metrics on `elemta-metrics:8080` |

They are deliberately not 2525/8025, so the cluster and the compose dev stack
can run side by side.

## What it leaves out

The compose dev stack also runs LDAP, Dovecot, ClamAV, Rspamd and a caching
DNS resolver. None of those are here, and `elemta.toml` in this directory
turns off what would otherwise point at them: SMTP AUTH, antivirus,
antispam and RBL checks. Mail for `local_domains` is delivered over LMTP to
`elemta-mailbox`; to deliver to a real mailbox server, remove
`lmtp-sink.yaml` from `kustomization.yaml` and point a Service named
`elemta-mailbox` at your LMTP server.

With AUTH off, nobody can relay: `allowed_relays` is empty, so only loopback
may send to domains outside `local_domains`. Do not set it to `"private"`
here. Behind a Service every client can look like a cluster address, and that
makes the server an open relay.

## First login

The dashboard starts with an empty users file, so nobody can log in until an
account exists:

```bash
kubectl -n elemta exec -it deploy/elemta -c web -- \
  sh -c 'exec /app/elemta --config /app/runtime-config/elemta.toml user add admin --role admin'
```

Then open http://localhost:30825.

## Smoke test

```bash
# Send one message to a local domain.
python3 - <<'EOF'
import smtplib
s = smtplib.SMTP("localhost", 30025)
s.sendmail("alice@sender.test", ["bob@example.com"],
           "From: alice@sender.test\r\nTo: bob@example.com\r\nSubject: k8s\r\n\r\nhello\r\n")
s.quit()
EOF

# The sink logs a running count every 10 seconds.
kubectl -n elemta logs deploy/elemta-mailbox --tail=3
```

## Changing the config

`elemta.toml` here is a template. On first start the pod copies it to the
`elemta-runtime-config` volume, and that copy is what the server reads and what
the dashboard saves to. Re-applying an edited template rolls the pod but does
not replace the copy, since that would discard whatever was saved in the UI.
To take the template again:

```bash
kubectl -n elemta exec deploy/elemta -c smtp -- rm /app/runtime-config/elemta.toml
kubectl -n elemta rollout restart deploy/elemta
```

## Running a local build

The manifests use `ghcr.io/evalalan/elemta:latest`, which CI publishes from
`main`. To run a build of your working tree on k3s, import it into k3s's own
containerd (it does not see Docker's images) and point kustomize at it:

```bash
docker build -t elemta:dev .
docker save elemta:dev | sudo k3s ctr images import -
```

Then in `kustomization.yaml` set the image to `newName: elemta`,
`newTag: dev`, and re-apply. For kind, use `kind load docker-image elemta:dev`
instead of the import.

## Installing k3s on Arch / CachyOS

k3s is a single binary with a systemd unit, and includes containerd, a
local-path storage provisioner and a service load balancer. It runs alongside
Docker without touching it.

```bash
# Traefik is not needed for SMTP and would take ports 80 and 443.
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -

# kubectl as your own user
sudo pacman -S --needed kubectl
mkdir -p ~/.kube
sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config
chmod 600 ~/.kube/config

kubectl get nodes
```

If a host firewall is on (ufw or firewalld), allow the pod and service
networks, or pods cannot reach each other or DNS:

```bash
sudo ufw allow from 10.42.0.0/16
sudo ufw allow from 10.43.0.0/16
```

To remove it again: `/usr/local/bin/k3s-uninstall.sh`.
