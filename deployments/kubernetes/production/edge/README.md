# Production edge component

This Kustomize component adds public TLS and traffic routing to `ha/`. It is
intended for a multi-node production overlay. It does not install the mail
stack's configuration, credentials, storage, or S3 service.

## Controllers and public addresses

Run `install-controllers.sh` with `EDGE_CONTEXT` set to the production kube
context. It installs pinned cert-manager and HAProxy Ingress Controller charts
and creates the `haproxy` IngressClass. Helm and a LoadBalancer implementation
are required on the target cluster. The HAProxy Service publishes only ports
80 and 443 and preserves the source address. Its two replicas have a
disruption budget.

Set the four values in `settings.env` before including this component. Public
DNS for the admin and webmail names must point to the HAProxy LoadBalancer;
port 80 must reach it for ACME HTTP-01 validation. The mail name must also
route port 80 to HAProxy so cert-manager can validate its certificate. Its
mail ports must reach one public address that forwards SMTP ports to `elemta-mail-public` and
mailbox ports to `elemta-mailbox-public`. If the cluster allocates a different
address to each Kubernetes Service, place one external layer-4 balancer in
front with port-specific backends or configure address sharing in the
LoadBalancer implementation. Do not publish both distinct addresses as A
records for the same name: clients would sometimes reach the wrong Service.
The ACME `Issuer`
uses Let's Encrypt production; use its staging URL during the first routing
test to avoid production rate limits.

An overlay can include it alongside `ha/`:

```yaml
resources:
  - ../ha
components:
  - edge
```

The overlay also must supply the `ha/` configuration and Secrets described
in the [Kubernetes README](../../README.md). Do not apply `ha/` or this
component alone. Edit `settings.env` to real hostnames and an ACME contact
first; the example names cannot receive public certificates.

## Application TLS configuration

cert-manager creates two automatically renewed Secrets in `elemta`:

- `elemta-mail-tls`, for the mail hostname, is mounted in the MTA at
  `/app/public-tls/tls.crt` and `/app/public-tls/tls.key`. The overlay's
  `elemta.toml` must point `[tls].cert_file` and `key_file` to those paths.
  The MTA reloads the pair when the mounted files change. The dashboard
  gets only `tls.crt` at the same path, for its health tab.
- The same mail Secret is mounted in the mailbox at
  `/etc/elemta/tls/cert.pem` and `key.pem`, matching the existing mailbox
  configuration. The mailbox reads the renewed files on new TLS handshakes.
  Set `[delivery].lmtp_tls_server_name` in the MTA config to the public mail
  hostname and clear `lmtp_tls_ca_file` so verification uses the system CA
  store; the development-only mailbox CA mount is removed by this component.
- `elemta-web-tls` covers admin and webmail. HAProxy terminates HTTPS and
  redirects HTTP to HTTPS. Webmail must set `secure_cookies = true`,
  `insecure_skip_verify = false`, and an HTTPS `recovery_url` in its production
  configuration. Set the dashboard's allowed origin to the admin HTTPS URL.

Admin and webmail stay HTTP inside the cluster, but NetworkPolicies admit
only the HAProxy controller pods. If webmail uses `trusted_proxies`, trust
only the controller pod addresses or the tightly scoped pod CIDR. Do not
publish the backend HTTP Services as LoadBalancers.

## Mail TCP listeners

Mail bypasses HAProxy. `elemta-mail-public` exposes SMTP 25 and submission
587; `elemta-mailbox-public` exposes IMAPS 993, IMAP STARTTLS 143, POP3 STLS
110, and ManageSieve 4190. Both use `externalTrafficPolicy: Local`, so the
external balancer must send traffic only to nodes with a ready endpoint.
That keeps the original address available to SMTP relay and rate-limit
checks. Keep 2588, the webmail-only submission listener, internal.

Check `kubectl -n elemta get certificate,ingress,svc` and confirm both
Certificates are Ready before changing public DNS. Verify HTTPS for admin
and webmail, SMTP STARTTLS on 25 and 587, IMAPS on 993, and an SMTP test
that records the client's actual public IP. Repeat after a certificate
renewal or a controlled Secret replacement.
