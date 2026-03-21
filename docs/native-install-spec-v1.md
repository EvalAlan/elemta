# Elemta Native Install Spec v1

## Status

Proposed baseline for first-class native Linux installation.

This document defines the **canonical native installation model** for Elemta across:

- RPM-based distributions
- DEB-based distributions

This is the source-of-truth direction for package layout, service model, config placement, and install profiles.

---

## Goals

Elemta should install and operate as a real Linux service without requiring:

- Docker
- Kubernetes
- vendor-specific `/opt` layouts

The native install model should be:

- distro-conventional
- operator-friendly
- upgrade-safe
- compatible with configuration management tools
- flexible enough to support multiple queue/backend profiles later

---

## Non-Goals

This spec does **not** yet define:

- exact package build pipeline implementation details
- final systemd hardening knobs
- DB migration tooling
- full post-install automation behavior
- distro repository publishing process

Those are follow-up tasks.

---

## Canonical Filesystem Layout

### Binaries

Install packaged executables under:

- `/usr/bin/elemta`
- `/usr/bin/elemta-cli`

Rationale:

- standard FHS-style placement
- avoids `/opt`
- works cleanly for both RPM and DEB packaging

> Note: if admin-only helpers emerge later, `/usr/sbin` may be reconsidered for specific binaries, but the baseline assumption for now is `/usr/bin`.

---

### Configuration

Install config under:

- `/etc/elemta/elemta.toml`
- `/etc/elemta/conf.d/*.toml`

Reserved optional directories for future use:

- `/etc/elemta/plugins.d/`
- `/etc/elemta/policies.d/`

Principles:

- package-owned defaults live in `/etc/elemta/`
- local admin changes must survive upgrades
- config should support layered overrides without requiring a single monolithic file forever

---

### Queue / Spool

Install queue and spool paths under:

- `/var/spool/elemta/`

Expected subdirectories for file-backed mode:

- `/var/spool/elemta/active/`
- `/var/spool/elemta/deferred/`
- `/var/spool/elemta/held/`
- `/var/spool/elemta/failed/`
- `/var/spool/elemta/quarantine/`
- `/var/spool/elemta/data/`
- `/var/spool/elemta/tmp/`

Rationale:

- matches operator expectations for an MTA spool
- keeps queue payload/state-like files out of generic application directories
- aligns with existing file queue instincts while leaving room for future backend abstraction

---

### Persistent Application State

Install persistent app state under:

- `/var/lib/elemta/`

Examples:

- sqlite DB (if sqlite backend is enabled)
- persistent runtime metadata
- future internal state files not appropriate for spool storage

Principle:

- `/var/lib/elemta` is for persistent application state
- `/var/spool/elemta` is for queue/spool workflow data

---

### Runtime State

Use:

- `/run/elemta/`

Examples:

- pid files (if needed)
- Unix sockets (if introduced)
- ephemeral runtime files

Managed via:

- `systemd`
- optionally `tmpfiles.d`

---

### Logs

Default logging target:

- `journald`

Optional file-based logging may later use:

- `/var/log/elemta/`

Baseline policy:

- default packaged installs should rely on journald
- file logs should be opt-in, not required for normal operation

Rationale:

- cleaner integration with native service management
- less rotation complexity by default
- better out-of-box behavior on modern Linux systems

---

## Service Identity

Create a dedicated system account:

- user: `elemta`
- group: `elemta`

Service should run as that user by default.

Principles:

- no root runtime unless absolutely required for a specific operation
- privilege for privileged port binding should be solved intentionally (capabilities, socket activation, or explicit runtime choice), not by defaulting to a root service

---

## Service Management Model

### Init system

`systemd` is the default supported native service manager.

Expected operator workflow:

```bash
systemctl enable elemta
systemctl start elemta
systemctl restart elemta
systemctl status elemta
journalctl -u elemta
```

### Baseline unit behavior

The packaged service should eventually support:

- dedicated user/group
- predictable restart behavior
- runtime directory creation
- clean shutdown behavior
- compatibility with standard hardening options where they do not break MTA realities

### Open question for follow-up

Need explicit decision on privileged SMTP binding model:

- bind directly as root then drop privileges?
- use capabilities?
- use socket activation?
- default to non-privileged ports unless explicitly configured otherwise?

This should be settled before finalizing packaged service hardening.

---

## Config Model

### Primary config

Canonical main config file:

- `/etc/elemta/elemta.toml`

### Layered config

Drop-ins under:

- `/etc/elemta/conf.d/*.toml`

Suggested future convention:

- `10-listener.toml`
- `20-queue.toml`
- `30-auth.toml`
- `40-tls.toml`
- `50-api.toml`
- `60-plugins.toml`

### Config principles

- simple installs can work with a single `elemta.toml`
- more advanced installs can split configuration into drop-ins
- package defaults should not overwrite admin-maintained configuration on upgrade
- configuration must be easy to manage with Ansible/Puppet/Salt/shell automation

---

## Native Install Profiles

The native install contract should support multiple deployment profiles without splitting the product into unrelated distributions.

### 1. Simple profile

Target:

- single-node enterprise installs
- relays
- lab/dev-like native deployments

Likely backend default:

- file queue backend

Characteristics:

- no external DB required
- simplest dependency story
- easiest operator onboarding path

---

### 2. Enhanced profile

Target:

- native installs that want richer queue metadata without external DB operations

Likely backend default:

- sqlite backend

Characteristics:

- embedded DB option
- richer metadata/state management
- still avoids separate DB service footprint

---

### 3. Platform profile

Target:

- serious enterprise/carrier/platform deployments
- future clustered queue/control plane behavior

Likely backend default:

- postgres backend

Characteristics:

- richer operational surface
- stronger concurrency and introspection story
- explicitly higher-complexity deployment model

---

## Package Outputs

Elemta should ship both:

- RPM packages
- DEB packages

Important constraint:

- these must implement **the same native install model**, not different product behaviors

Meaning:

- same path layout
- same config structure
- same service model
- same upgrade semantics where distro tooling allows

---

## Packaging Toolchain Direction

### Recommended initial approach

Use:

- **GoReleaser** for release orchestration
- **nfpm** for native package generation

### Why

- works well with Go projects
- can produce both RPM and DEB artifacts
- reduces packaging boilerplate for initial serious packaging work
- fast enough to get real native artifacts into testing without overcommitting to handcrafted distro packaging on day one

### Caveat

If packaging complexity eventually outgrows this approach, the project may later adopt more distro-native packaging workflows (`rpmbuild`, `debhelper`, etc.).

For now, the goal is to establish a **credible, testable native package pipeline**, not to prematurely drown in packaging bureaucracy.

---

## Package Composition Direction

### Base package: `elemta`

Should contain:

- main server binary
- CLI/admin binary as appropriate
- default config skeleton
- systemd unit
- user/group setup definitions
- runtime/state/spool directory definitions

### Possible optional packages later

- `elemta-tools`
- `elemta-postgres`
- `elemta-sqlite`
- `elemta-plugin-*`

These are future refinements, not required to finalize the native install contract.

---

## Upgrade Semantics

The package/install model must preserve operator trust.

### Requirements

- local config should survive package upgrades
- upgrades must not delete spool/state data
- service restart/reload behavior should be predictable
- backend migrations (where applicable) should not be hidden, unsafe side effects

### Principle

Native install UX should feel safe to operators who manage long-lived mail systems.

---

## Configuration Management Expectations

The install model should be straightforward to automate with:

- Ansible
- Puppet
- Salt
- shell provisioning

To support that, Elemta should eventually expose at least:

- config validation
- effective config rendering
- install sanity checks / doctor-style validation

Candidate future commands:

```bash
elemta config validate
elemta config dump-effective
elemta doctor
```

---

## Decisions Made So Far

### Settled

- no `/opt`
- support both RPM and DEB
- use standard Linux/FHS-style paths
- native installs are first-class, not second-class behind Docker/Kubernetes
- package/service/config behavior should be shared across RPM and DEB outputs
- journald is the default logging target
- `GoReleaser + nfpm` is the current recommended packaging toolchain direction

### Not Yet Final

- exact unit file hardening
- privileged port binding strategy
- final package split strategy
- backend migration mechanics
- native repository/publishing strategy

---

## Next Implementation Tasks

1. create example packaged config tree in-repo
2. draft systemd unit file
3. draft `nfpm`/release config
4. define user/group and directory creation behavior
5. define first supported native install target matrix
6. test native package artifacts on at least one RPM-family and one DEB-family distro

---

## Working Summary

Elemta should behave like a real Linux MTA/service installation:

- binaries in `/usr`
- config in `/etc/elemta`
- spool in `/var/spool/elemta`
- persistent state in `/var/lib/elemta`
- runtime files in `/run/elemta`
- logs in journald by default
- same install model across RPM and DEB
- native packages built initially via GoReleaser + nfpm

This is the baseline contract for future native packaging work.
