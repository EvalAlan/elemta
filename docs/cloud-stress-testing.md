# Cloud stress testing

Run the load generator from a workstation so its CPU and memory do not compete
with the cloud server. It needs Python 3.9+, SSH key access to the deployment
user, and a trusted public certificate on the server. No Python packages are
required.

```sh
python3 scripts/dev/cloud_stress.py --host dev.example.net --ssh-user deploy --profile smoke
python3 scripts/dev/cloud_stress.py --host dev.example.net --ssh-user deploy --profile ramp
```

The hostname, optional `--domain`, and SSH user are runtime arguments. Keep real
deployment values and reports out of tracked files. The selected domain must
already be configured locally; the script never adds domains or changes service
settings, scanner configuration, firewall rules or delivery destinations.

The smoke profile submits 108 messages: 20 at one client, 80 at four clients,
and eight with 512 KiB bodies. The ramp profile submits 1,332 messages across
one, four and eight clients, including 32 with 512 KiB bodies. Each phase waits
for IMAP-confirmed delivery and checks every generated Message-ID for missing
or duplicate messages. SMTP sessions use verified STARTTLS on 587 and reuse
connections, so DATA latency and delivered messages per second describe useful
work rather than repeated handshakes. Delivery rate includes sending and queue
drain time; DATA latency measures SMTP transaction completion, not delivery.

After delivery, concurrent IMAPS readers select, search and fetch 50-message
envelopes and body structures. The ramp reaches 32 readers. Webmail clients
sign in over HTTPS, load the mailbox and request folder counts. This exercises
the HTTP application, not browser rendering, JavaScript, SSE or rich compose.
The phases run sequentially; this is a starting baseline rather than a mixed
workload or a claim about maximum supported users. Authenticated SMTP traffic
does not exercise inbound DKIM/ARC verification or delivery to external MXs.

Every run creates a unique 512 MiB quota account with a random password. All
recipients are that account on the configured local domain, and no mail goes
to external domains. The account and mail are logically deleted after success;
physical bodies follow the mailbox's configured retention/garbage collection.
No other mailbox is modified.

The runner samples host memory, swap, load, disk space, queue depth and Docker
resource/health/restart state. It stops on service failure/restart/OOM, a growing
failed queue, fewer than 256 MiB available RAM, less than 5 GiB disk space, or
more than 2,000 active/deferred queue entries. A failed SMTP operation stops
new submissions instead of retrying an uncertain delivery. Phase deadlines
default to 180 seconds. Socket operations allow 20 seconds and SSH/resource
probes allow 45 seconds to finish; stopping waits for pending workers. Existing
rate and connection limits remain active.

Reports and temporary credentials are written with private permissions under
the ignored `.notes/stress-runs/<run>/` directory. `report.json` contains phase
throughput, latency percentiles, errors and resource samples. `fixture.json`
contains credentials only while the fixture exists; after successful cleanup
it records deletion without retaining the password. A custom output directory
inside the checkout must also be ignored. Reports identify the actual host and
must not be committed or published unchanged.

Failed or interrupted runs preserve their account for inspection so queued
messages do not turn into bounces. Inspect the private report and queue before
removing that exact account with `provision delete-account <address> --confirm
<address>`. Any remaining fixture password can be reset with the provisioning
CLI. Do not delete shared queue files or mailbox body volumes to clean up a run.
