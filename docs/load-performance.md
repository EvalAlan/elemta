# Load scaling on the development host (2026-10-20)

Run `20261020T195401-5f3c` used 30-second steps, 100 accounts with 200 seeded messages each and a
5,000-message public corpus. A worker repeats one complete protocol action;
SMTP actions open a connection, authenticate and submit a message. The mixed
run uses SMTP:IMAP:POP3:webmail workers in a 1:2:1:2 ratio. These are
throughput measurements of this host and workload, not capacity promises.

| Workload | Last useful step | Throughput there | What limits the next step |
|---|---:|---:|---|
| SMTP alone | ~16 workers | 15.9 messages/s | Throughput reaches only 17.0 at 64 workers while p95 rises from 1.6 to 5.0 s. ClamAV is the busiest container at 65–79% CPU around the knee; DATA time grows most. |
| IMAP alone | No stop through 64 workers | 47.4 actions/s | Still growing. Mailbox Postgres reaches 79–90% CPU at 32–64 workers; p95 rises to 1.9 s. |
| POP3 alone | No stop through 64 workers | 61.4 actions/s | Still growing. Mailbox Postgres reaches 87% CPU at 64 workers; p95 rises to 1.4 s. |
| Webmail alone | ~8 workers | 13.3 actions/s | About 13–14 actions/s through 64 workers, while p95 rises from 1.5 to 9.0 s. Mailbox Postgres reaches 72–88% CPU and connections rise from 10 to 17. |
| Mixed | ~2 step units for webmail; ~4–8 for IMAP | Webmail 7.0 and IMAP 7.9–9.9 actions/s | At 16 units webmail falls to 3.3 actions/s with 22.2 s p95; IMAP stays near 10, POP3 reaches 5.2 and SMTP 7.1. Database connections reach 17 by step 4 and total container CPU stays near 160–165%. |

The mailbox database is the most consistent shared pressure: login, list,
search and open times all increase under mixed load. The measurements show
connection growth and database CPU but do not separately measure time waiting
for a pool slot. TLS and directory work are included in the login phase, so
the run cannot assign their exact shares. Directory and Rspamd CPU were low
relative to Postgres during mixed load; neither was the leading measured CPU
consumer. SMTP alone has a different profile: ClamAV CPU and DATA latency rise
as throughput flattens. These are leads for profiling, not proof that raising
one pool limit or disabling a scanner would increase throughput.

The original run submitted 2,499 messages; all 2,499 arrived exactly once.
Later 8-worker and 16-worker checks submitted and delivered another 716 and
1,704 messages respectively, with no missing or duplicate deliveries.
