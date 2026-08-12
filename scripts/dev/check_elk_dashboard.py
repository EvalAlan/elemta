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


def main():
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
