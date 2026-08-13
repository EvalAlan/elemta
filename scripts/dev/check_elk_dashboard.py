#!/usr/bin/env python3
"""Check that every dashboard panel would actually draw something.

A Kibana panel that queries a field nobody logs does not fail — it renders an
empty chart, which looks identical to a quiet server. That is the failure this
guards against: each panel's query is run against Elasticsearch here, so a
panel with no data is a line of output rather than something to notice later
in a browser.

  python3 scripts/dev/check_elk_dashboard.py
"""

import json
import subprocess
import sys
import urllib.error
import urllib.request

ES = "http://localhost:9200"

# (panel, human description, ES query). These mirror the queries in
# build_elk_dashboard.py; if a panel there changes, change it here too.
CHECKS = [
    ("elemta-throughput", "accepted messages",
     {"match": {"event_type": "message_accepted"}}),
    ("elemta-outcomes", "rejected messages",
     {"bool": {"must": [{"match_phrase": {"msg": "message_scanned"}},
                        {"term": {"passed": False}}]}}),
    ("elemta-scan-verdicts", "scan verdicts",
     {"match_phrase": {"msg": "message_scanned"}}),
    ("elemta-scan-verdicts", "virus verdicts",
     {"term": {"virus_found": True}}),
    ("elemta-scan-verdicts", "spam verdicts",
     {"term": {"spam_detected": True}}),
    ("elemta-backlog", "messages leaving the queue",
     {"term": {"event_type": "delivery"}}),
    ("elemta-spam-scores", "messages carrying a spam score",
     {"exists": {"field": "spam_score"}}),
    ("elemta-latency", "delivery events with a delay",
     {"bool": {"must": [{"match": {"event_type": "delivery"}},
                        {"exists": {"field": "total_delay_ms"}}]}}),
    ("elemta-problems", "warnings and errors",
     {"terms": {"log.level": ["WARN", "ERROR"]}}),
    ("elemta-components", "events carrying a component",
     {"exists": {"field": "component"}}),
]


def es(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(ES + path, data=data, method="POST" if data else "GET")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.URLError as exc:
        raise SystemExit(f"Elasticsearch is not reachable at {ES}: {exc}\n"
                         f"Start it with 'make elk-up'.")


def dropped_events():
    """Count events Filebeat threw away rather than shipped.

    Elasticsearch rejects a document whose field collides with an ECS object —
    Elemta logs `service`, `server` and `error` as plain strings, ECS defines
    all three as objects — and Filebeat drops it with a warning nobody reads.
    This has been found three times by accident. Once it cost 71% of the log,
    once 33%, and in both cases the dashboard looked merely quiet rather than
    broken, which is the whole problem: a silent shipper and an idle server
    draw the same picture.
    """
    try:
        out = subprocess.run(
            ["docker", "logs", "elemta-filebeat", "--since", "10m"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout + out.stderr).count("dropping event")


def main():
    dropped = dropped_events()
    if dropped is None:
        print("Could not read Filebeat's log; skipping the dropped-event check.\n")
    elif dropped:
        print(f"WARNING: Filebeat dropped {dropped} events in the last 10 minutes.\n"
              f"  Elasticsearch is rejecting them, usually because a field collides\n"
              f"  with an ECS object type. Find the field by replaying real log lines\n"
              f"  as _bulk create ops against the elemta-* data stream and reading the\n"
              f"  per-item errors; then add a rename to deployments/elk/filebeat.yml.\n")
    else:
        print("Filebeat is not dropping events.\n")

    total = es("/elemta-*/_count").get("count", 0)
    if total == 0:
        raise SystemExit("The elemta-* index is empty. Send some mail first:\n"
                         "  python3 scripts/dev/stress_corpus.py --messages 200")
    print(f"{total} events indexed\n")

    empty = []
    for panel, label, query in CHECKS:
        count = es("/elemta-*/_count", {"query": query}).get("count", 0)
        mark = "ok  " if count else "EMPTY"
        print(f"  {mark} {panel:24} {label:34} {count}")
        if not count:
            empty.append(f"{panel} ({label})")

    if empty:
        print("\nThese panels would render empty:")
        for item in empty:
            print(f"  - {item}")
        return 1
    print("\nEvery panel has data.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
