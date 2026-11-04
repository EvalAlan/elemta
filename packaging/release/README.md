# Elemta release tarball

| File | What it is |
|---|---|
| `elemta` | The server: MTA, mailbox service, webmail, admin console and migration tool |
| `elemta-cli` | The command line client for a running server |
| `web/` | The admin console's web files |
| `elemta.toml` | A starter configuration, for trying Elemta on one machine |
| `LICENSE`, `LICENSING.md` | Elemta's license, the GPL version 3 |
| `third-party/` | The license files of the Go modules built into the binaries |

Elemta's webmail bundles OpenPGP.js, under the LGPL. Its license is in
`third-party/openpgp.LICENSE`, and the source of everything else is at
<https://github.com/EvalAlan/elemta>.

## Try it

Run these from this directory. It stays on 127.0.0.1, on unprivileged ports.

```bash
chmod 600 elemta.toml
mkdir -p data

./elemta --config elemta.toml user add admin --role admin
./elemta --config elemta.toml server &
./elemta --config elemta.toml web &
```

SMTP is on 127.0.0.1:2525 and the admin console on <http://127.0.0.1:8025>. Both
take a few seconds to start. Warnings about `/var/log/elemta`, plugins, ClamAV,
Rspamd and Valkey are expected here: this configuration runs without them.

## Run it for real

This configuration has no TLS, no mailboxes and no webmail. A full mail server
also needs PostgreSQL, Valkey and a directory, so most people should use the Docker
Compose setup, which runs all of it from the same code:

- [Getting started](https://github.com/EvalAlan/elemta#quick-start)
- [One internet-facing server](https://github.com/EvalAlan/elemta/blob/main/docs/cloud-dev.md)
- [Production on Docker Compose](https://github.com/EvalAlan/elemta/blob/main/docs/production-compose.md)
