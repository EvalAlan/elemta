# Architecture

How Elemta's parts fit together, and how each way of running it lays them out:
the Docker Compose development stack, the cloud server, and Kubernetes. The
diagrams are Mermaid, which GitHub renders.

## Components and mail flow

Every deployment has the same parts. The **MTA** (`elemta`) takes mail in and
sends it out. The **mailbox service** stores it and serves it over IMAP and
POP3. The **webmail** is how people read it in a browser. The **admin
console** runs the server. An **LDAP directory** holds the accounts.

```mermaid
flowchart LR
    internet(["Sending mail servers"])
    remote(["Recipients' mail servers"])
    apps(["Mail apps<br/>Thunderbird, phones"])
    browser(["Web browser"])
    admin(["Administrator"])

    subgraph mta["Elemta MTA"]
        smtp["SMTP 25<br/>submission 587"]
        checks["SPF · DKIM · DMARC · ARC<br/>ClamAV · Rspamd · RBLs"]
        queue[("Queue")]
        smtp --> checks --> queue
    end

    subgraph mailbox["Mailbox service"]
        lmtp["LMTP + Sieve filters"]
        imap["IMAP 993/143 · POP3 110"]
        msieve["ManageSieve"]
        secapi["Security API<br/>2FA · app passwords"]
    end

    pg[("Postgres<br/>metadata")]
    bodies[("File or S3<br/>message bodies")]
    webmail["Webmail<br/>mail · calendar · contacts · tasks"]
    console["Admin console"]

    internet -->|"inbound mail"| smtp
    apps -->|"send"| smtp
    queue -->|"local recipients, LMTP over TLS"| lmtp
    queue -->|"remote recipients, DKIM-signed"| remote
    apps -->|"read"| imap
    browser -->|"HTTPS"| webmail
    webmail -->|"IMAP, internal"| imap
    webmail -->|"ManageSieve"| msieve
    webmail -->|"submission"| smtp
    webmail -->|"2FA, app passwords"| secapi
    admin --> console
    console --> queue
    lmtp & imap & secapi --> pg
    lmtp & imap --> bodies
```

Every part looks accounts up in the **LDAP directory** (addresses, aliases,
quotas, groups and passwords), so it is left out of the diagram. SMTP AUTH
also asks the mailbox service's security API whether a user requires app
passwords.

### A message from the internet to a mailbox

```mermaid
sequenceDiagram
    participant S as Sending server
    participant M as Elemta MTA
    participant Q as Queue
    participant B as Mailbox service
    participant U as User's mail app
    S->>M: SMTP on 25: MAIL FROM, RCPT TO
    M->>M: RCPT checked against LDAP (unknown users refused)
    S->>M: DATA
    M->>M: SPF, DKIM, DMARC, ARC, antivirus, spam
    M->>Q: accepted (250)
    Q->>B: LMTP over STARTTLS
    B->>B: Sieve: filters, out-of-office, redirects
    B->>B: store metadata (Postgres) and body (file/S3)
    U->>B: IMAP IDLE wakes, client fetches
```

## Docker Compose: the development stack

`make install-dev` runs `deployments/compose/docker-compose.yml`. Every
service is on one bridge network, `elemta_network` (10.253.53.0/24), and
reaches the others by container name. The mailbox service runs as two
replicas behind HAProxy, so restarting one doesn't interrupt mail.

```mermaid
flowchart TB
    subgraph host["Host ports"]
        p2525["2525 SMTP"]
        p2587["2587 submission"]
        p993["993 IMAPS"]
        p8027["8027 webmail"]
        p8025["8025 admin console"]
        p8026["8026 Roundcube (full)"]
    end

    subgraph net["elemta_network 10.253.53.0/24"]
        node0["elemta-node0<br/>MTA"]
        web["elemta-web<br/>admin console"]
        webmail["elemta-webmail<br/>10.253.53.250"]
        dns["elemta-dns<br/>Unbound resolver 10.253.53.53"]
        haproxy["elemta-mailbox<br/>HAProxy"]
        mba["elemta-mailbox-a"]
        mbb["elemta-mailbox-b"]
        db[("elemta-mailbox-db<br/>Postgres")]
        valkey[("elemta-valkey")]
        clamav["elemta-clamav (full)"]
        rspamd["elemta-rspamd (full)"]
        rc["elemta-roundcube (full)"]
    end

    p2525 & p2587 --> node0
    p993 --> haproxy
    p8027 --> webmail
    p8025 --> web
    p8026 --> rc

    node0 -->|"LMTP 2424"| haproxy
    node0 --> dns
    node0 --> clamav
    node0 --> rspamd
    rspamd --> dns
    node0 & web --> valkey
    webmail -->|"IMAP 1143 · Sieve 4190 · API 8080"| haproxy
    webmail -->|"submission 2587"| node0
    webmail -->|"sessions"| valkey
    rc --> haproxy
    rc --> node0
    haproxy --> mba & mbb
    mba & mbb --> db
```

`elemta-ldap` (OpenLDAP) is on the same network and used by the MTA, admin
console, webmail and mailbox replicas; its connections are left out to keep the
diagram readable.

Volumes keep state across restarts: `elemta_queue` (the queue),
`elemta_config` (the configuration the admin console edits), `mailbox_metadata`
(Postgres), `mailbox_bodies` (message files), `ldap_data` and `valkey_data`.

## The cloud server

[`scripts/cloud-deploy.sh`](cloud-dev.md) runs the same stack on one
internet-facing host, with `docker-compose.cloud.yml` layered on top. Only the
mail and web ports are public. Everything else is bound to 127.0.0.1 and
reached over SSH. Two layers filter traffic: firewalld for the host, and an
nftables guard for Docker's published ports, which bypass firewalld.

```mermaid
flowchart TB
    internet(["Internet"])

    subgraph hostfw["Host"]
        fw["firewalld<br/>ssh · 25 · 80 · 443 · 587 · 993 · 143 · 110"]
        guard["nftables docker-guard<br/>drops any other published port"]
    end

    subgraph stack["Compose stack + cloud overlay"]
        caddy["Caddy<br/>Let's Encrypt · HTTPS · autoconfig"]
        node0["MTA<br/>25 → 2525 · 587 → 2587"]
        haproxy["HAProxy<br/>993 · 143 · 110"]
        webmail["Webmail"]
        mailbox["Mailbox replicas"]
        private["Admin console 8025 · LDAP · Postgres<br/>Valkey · Rspamd · metrics · ManageSieve<br/>(127.0.0.1 only)"]
    end

    certs[("Certificate<br/>.secrets/mailbox-tls")]
    timer["elemta-cert-sync.timer<br/>twice a day"]

    internet --> fw --> guard
    guard -->|"80, 443"| caddy
    guard -->|"25, 587"| node0
    guard -->|"993, 143, 110"| haproxy
    caddy --> webmail
    haproxy --> mailbox
    caddy -. "issues and renews" .-> timer
    timer -->|"copies"| certs
    certs -->|"read on change"| node0 & mailbox
    admin(["Administrator"]) -->|"ssh -L 8025"| private
```

## Kubernetes

Kubernetes manifests are kustomize overlays in `deployments/kubernetes`,
written for a single-node k3s cluster. `make k8s-install-dev*` applies the dev
overlays. The standalone overlay runs the MTA alone from the published image.

```mermaid
flowchart TB
    base["base/<br/>namespace · Elemta pod · sink · Valkey · volumes"]
    minimal["dev/minimal<br/>+ DNS · LDAP · Dovecot · host ports"]
    full["dev/full"]
    bench["dev/bench"]
    postgres["dev/postgres"]
    standalone["standalone/<br/>published image · own config"]
    scanners[["component: scanners<br/>ClamAV · Rspamd"]]
    roundcube[["component: roundcube"]]
    pgc[["component: postgres<br/>queue backend"]]

    base --> minimal
    base --> standalone
    minimal --> full & bench & postgres
    scanners --> full & bench
    roundcube --> full
    pgc --> postgres
```

The dev stack's pods and how they connect. The Elemta pod runs the MTA and
the admin console as two containers sharing the queue and runtime
configuration. Services keep their Compose names, so the same `elemta.toml`
works in both.

```mermaid
flowchart LR
    subgraph lb["k3s LoadBalancer (host ports)"]
        h1["2525 · 2587"]
        h2["8025"]
        h3["14143 · 4190"]
        h4["8026 (full)"]
    end

    subgraph ns["namespace elemta"]
        subgraph pod["Elemta pod"]
            smtp["MTA container"]
            dash["admin console container"]
        end
        dns["elemta-dns<br/>10.43.53.53"]
        ldap[("elemta-ldap")]
        dovecot["elemta-dovecot<br/>IMAP · LMTP · Sieve"]
        valkey[("elemta-valkey")]
        sink["elemta-sink<br/>(bench)"]
        clamav["elemta-clamav (full, bench)"]
        rspamd["elemta-rspamd (full, bench)"]
        rc["elemta-roundcube (full)"]
        pg[("elemta-postgres<br/>(postgres overlay)")]
    end
    kubedns["kube-dns 10.43.0.10"]

    h1 --> smtp
    h2 --> dash
    h3 --> dovecot
    h4 --> rc
    smtp -->|"LMTP"| dovecot
    smtp -.->|"bench: discard"| sink
    smtp --> clamav & rspamd & dns & valkey & ldap
    smtp -.-> pg
    dns -->|"cluster.local"| kubedns
    dovecot --> ldap
    rc --> dovecot & smtp
```

> **Kubernetes still runs Dovecot.** The Kubernetes dev overlay hasn't been
> moved to the mailbox service and webmail yet. Until it is, use the Compose
> stack or the cloud server for the full mail platform.
