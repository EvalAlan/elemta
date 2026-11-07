#!/bin/bash
# Two mailbox cells behind the cell router on the local dev cluster
# (deployments/kubernetes/dev/cells, docs/mailbox-cells.md).
#
#   scripts/k8s-cells-dev.sh up      build images, make secrets, apply, seed
#   scripts/k8s-cells-dev.sh seed    (re)create the test domains and users
#   scripts/k8s-cells-dev.sh move <address> <cell>   move a mailbox
#   scripts/k8s-cells-dev.sh load-policy             abuse limits log only, for load tests
#   scripts/k8s-cells-dev.sh down    delete the namespace
#
# Test accounts (password in .secrets/cells/user-password):
#   alice@a.test, carol@a.test   domain a.test, placed in cell a
#   bob@b.test                   domain b.test, placed in cell b
#   dave@c.test                  domain c.test, placed nowhere: cell a, the default
# The router is published on the host: IMAP 21143, IMAPS 21993, POP3 21110,
# LMTP 21424, ManageSieve 21190, HTTP 21080.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ns=elemta-cells
dir="$root/deployments/kubernetes/dev/cells"
secrets="$root/deployments/compose/.secrets/cells"

seed() {
    local pw
    pw=$(cat "$secrets/user-password")
    local ldif=""
    ldif+=$'dn: ou=people,dc=example,dc=com\nobjectClass: organizationalUnit\nou: people\n\n'
    ldif+=$'dn: ou=domains,dc=example,dc=com\nobjectClass: organizationalUnit\nou: domains\n\n'
    ldif+=$'dn: ou=groups,dc=example,dc=com\nobjectClass: organizationalUnit\nou: groups\n\n'
    for d in a b; do
        ldif+="dn: elemtaDomainName=$d.test,ou=domains,dc=example,dc=com"$'\n'
        ldif+=$'objectClass: elemtaMailDomain\nobjectClass: elemtaMailboxPlacement\n'
        ldif+="elemtaDomainName: $d.test"$'\n'"elemtaMailboxCell: $d"$'\n\n'
    done
    local n=6000
    for u in alice@a.test carol@a.test bob@b.test dave@c.test; do
        n=$((n + 1))
        ldif+="dn: uid=$u,ou=people,dc=example,dc=com"$'\n'
        ldif+=$'objectClass: inetOrgPerson\nobjectClass: posixAccount\nobjectClass: elemtaMailAccount\n'
        ldif+="uid: $u"$'\n'"mail: $u"$'\n'"cn: ${u%@*}"$'\n'"sn: ${u%@*}"$'\n'
        ldif+="uidNumber: $n"$'\n'"gidNumber: $n"$'\n'"homeDirectory: /nonexistent"$'\n'"accountStatus: active"$'\n\n'
    done
    printf '%s' "$ldif" | kubectl -n "$ns" exec -i deploy/elemta-ldap -- ldapadd -c -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 || true
    for u in alice@a.test carol@a.test bob@b.test dave@c.test; do
        kubectl -n "$ns" exec deploy/elemta-ldap -- ldappasswd -Q -Y EXTERNAL -H ldapi:/// -s "$pw" "uid=$u,ou=people,dc=example,dc=com" >/dev/null
    done
    echo "seeded: alice@a.test carol@a.test (cell a), bob@b.test (cell b), dave@c.test (default); password in $secrets/user-password"
}

case "${1:-up}" in
up)
    # Images reach the cluster through a registry on localhost:5000, which
    # containerd pulls from over plain HTTP: no sudo for "k3s ctr import",
    # and it works whether k3s runs on Docker or its own containerd.
    if ! docker ps --format '{{.Names}}' | grep -qx cells-registry; then
        docker run -d --rm --name cells-registry -p 127.0.0.1:5000:5000 registry:2 >/dev/null
    fi
    if ! docker image inspect localhost:5000/valkey:8-alpine >/dev/null 2>&1; then
        docker pull -q valkey/valkey:8-alpine >/dev/null
        docker tag valkey/valkey:8-alpine localhost:5000/valkey:8-alpine
    fi
    docker push -q localhost:5000/valkey:8-alpine >/dev/null
    for image in elemta-mailbox elemta-ldap; do
        docker build -q -t "localhost:5000/$image:scaling" -f "$root/docker/${image#elemta-}/Dockerfile" "$root" >/dev/null
        docker push -q "localhost:5000/$image:scaling" >/dev/null
    done
    mkdir -p "$secrets"
    chmod 700 "$secrets"
    if [ ! -f "$secrets/cert.pem" ]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 -subj /CN=cells-dev \
            -addext "subjectAltName=DNS:mailbox-a,DNS:mailbox-b,DNS:router,DNS:localhost,IP:127.0.0.1" \
            -keyout "$secrets/key.pem" -out "$secrets/cert.pem" 2>/dev/null
        openssl rand -hex 16 >"$secrets/ldap-admin-password"
        openssl rand -hex 16 >"$secrets/pg-password"
        openssl rand -hex 12 >"$secrets/user-password"
        openssl rand -hex 24 >"$secrets/admin-token"
        chmod 600 "$secrets"/*
    fi
    kubectl apply -f - <<<"$(kubectl create namespace "$ns" --dry-run=client -o yaml)" >/dev/null
    pg=$(cat "$secrets/pg-password")
    kubectl -n "$ns" create secret generic elemta-cells --dry-run=client -o yaml \
        --from-file=ldap-admin-password="$secrets/ldap-admin-password" --from-file=pg-password="$secrets/pg-password" | kubectl apply -f - >/dev/null
    kubectl -n "$ns" create secret generic elemta-cells-env --dry-run=client -o yaml \
        --from-literal=ELEMTA_CELL_A_DSN="postgres://mailbox:$pg@pg-a:5432/mailbox?sslmode=disable" \
        --from-literal=ELEMTA_CELL_B_DSN="postgres://mailbox:$pg@pg-b:5432/mailbox?sslmode=disable" \
        --from-literal=ELEMTA_MAILBOX_LDAP_DN="cn=admin,dc=example,dc=com" \
        --from-literal=VALKEY_ADDR="valkey:6379" \
        --from-file=ELEMTA_MAILBOX_LDAP_PASSWORD="$secrets/ldap-admin-password" \
        --from-file=ELEMTA_MAILBOX_ADMIN_TOKEN="$secrets/admin-token" | kubectl apply -f - >/dev/null
    # Generic, not type tls: the services read cert.pem and key.pem.
    kubectl -n "$ns" delete secret elemta-cells-tls --ignore-not-found >/dev/null
    kubectl -n "$ns" create secret generic elemta-cells-tls \
        --from-file=cert.pem="$secrets/cert.pem" --from-file=key.pem="$secrets/key.pem" >/dev/null
    kubectl -n "$ns" create configmap elemta-cells-config --dry-run=client -o yaml \
        --from-file="$dir/mailbox-a.toml" --from-file="$dir/mailbox-b.toml" --from-file="$dir/router.toml" | kubectl apply -f - >/dev/null
    kubectl apply -f "$dir/cells.yaml" >/dev/null
    kubectl -n "$ns" rollout status deploy/elemta-ldap --timeout=180s >/dev/null
    kubectl -n "$ns" rollout status deploy/valkey --timeout=180s >/dev/null
    kubectl -n "$ns" exec deploy/valkey -- valkey-cli DEL elemta:abuse:policy >/dev/null
    seed
    # A changed image or configuration needs new pods.
    kubectl -n "$ns" rollout restart deploy/mailbox-a deploy/mailbox-b deploy/router >/dev/null
    for d in mailbox-a mailbox-b router; do kubectl -n "$ns" rollout status "deploy/$d" --timeout=300s >/dev/null; done
    kubectl -n "$ns" get pods
    ;;
seed) seed ;;
load-policy)
    # Log-only abuse limits, for load tests that open thousands of
    # connections from this one machine. "up" again restores enforcing.
    kubectl -n "$ns" exec deploy/valkey -- valkey-cli SET elemta:abuse:policy \
        '{"mode":"log","connections_per_address":25,"connections_per_minute":120,"failures_per_address":50,"failures_per_network":200,"accounts_per_address":10,"addresses_per_account":20,"messages_per_address_per_hour":1000,"outbound_recipients_per_hour":500,"window_minutes":15,"block_minutes":15,"max_block_hours":24,"firewall":"log","allowlist":[],"alert_email":[]}' >/dev/null
    echo "abuse limits now log only"
    ;;
move)
    # scripts/k8s-cells-dev.sh move carol@a.test b: a Job that mounts both
    # cells' bodies runs elemta mailbox move-account.
    address=${2:?address}
    to=${3:?cell}
    from=a
    [ "$to" = a ] && from=b
    job="move-$(date +%s)"
    kubectl -n "$ns" apply -f - >/dev/null <<YAML
apiVersion: batch/v1
kind: Job
metadata: { name: $job, namespace: $ns }
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      securityContext: { runAsNonRoot: true, runAsUser: 1001, runAsGroup: 1001, fsGroup: 1001 }
      containers:
        - name: move
          image: localhost:5000/elemta-mailbox:scaling
          args: ["mailbox", "move-account", "--config", "/etc/cells/mailbox-$from.toml", "--to-config", "/etc/cells/mailbox-$to.toml",
                 "--to-cell", "$to", "--address", "$address", "--purge", "--settle", "35s"]
          envFrom: [{ secretRef: { name: elemta-cells-env } }]
          volumeMounts:
            - { name: config, mountPath: /etc/cells, readOnly: true }
            - { name: tls, mountPath: /etc/elemta/tls, readOnly: true }
            - { name: bodies-a, mountPath: /var/lib/elemta/bodies-a }
            - { name: bodies-b, mountPath: /var/lib/elemta/bodies-b }
      volumes:
        - { name: config, configMap: { name: elemta-cells-config } }
        - { name: tls, secret: { secretName: elemta-cells-tls } }
        - { name: bodies-a, persistentVolumeClaim: { claimName: bodies-a } }
        - { name: bodies-b, persistentVolumeClaim: { claimName: bodies-b } }
YAML
    kubectl -n "$ns" wait --for=condition=complete "job/$job" --timeout=300s >/dev/null || {
        kubectl -n "$ns" logs "job/$job"
        exit 1
    }
    kubectl -n "$ns" logs "job/$job"
    ;;
down)
    kubectl delete namespace "$ns" --wait=true
    docker rm -f cells-registry >/dev/null 2>&1 || true
    ;;
*)
    echo "usage: $0 up|seed|move <address> <cell>|down" >&2
    exit 2
    ;;
esac
