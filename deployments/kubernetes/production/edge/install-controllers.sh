#!/usr/bin/env bash
set -euo pipefail

# A context is required because this installs cluster-wide controllers and
# CRDs, not just resources in the Elemta namespace.
: "${EDGE_CONTEXT:?Set EDGE_CONTEXT to the target production kube context}"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

helm --kube-context "$EDGE_CONTEXT" upgrade --install cert-manager \
  oci://quay.io/jetstack/charts/cert-manager \
  --version v1.21.2 \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true --wait

helm --kube-context "$EDGE_CONTEXT" upgrade --install haproxy-kubernetes-ingress \
  oci://ghcr.io/haproxytech/helm-charts/kubernetes-ingress \
  --version 1.54.2 \
  --namespace haproxy-controller --create-namespace \
  --values "$script_dir/haproxy-values.yaml" --wait

kubectl --context "$EDGE_CONTEXT" wait \
  --for=condition=Established crd/certificates.cert-manager.io --timeout=120s
kubectl --context "$EDGE_CONTEXT" get ingressclass haproxy
