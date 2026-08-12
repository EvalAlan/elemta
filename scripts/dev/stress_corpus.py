#!/usr/bin/env python3
"""Drive the message corpus at volume, so there is something worth looking at.

A load test that sends one kind of message answers "how fast" and nothing else.
The corpus in tests/corpus carries clean text, clean HTML, a GTUBE spam sample
and an EICAR virus sample, so sending a mix produces the spread a dashboard
needs: throughput alongside what the scanners actually found, per message type.

Every message carries an X-Elemta-Stress-Run header naming the run, which is
what lets a dashboard show one run rather than everything the server has ever
done.

  python3 scripts/dev/stress_corpus.py --messages 400 --concurrency 8
"""

import argparse
import email.utils
import os
import queue
import random
import smtplib
import ssl
import sys
import threading
import time
import uuid
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CORPUS_DIR = os.path.join(REPO, "tests", "corpus")

# Weighted the way real mail arrives rather than evenly: most of it is fine.
# An even split would make the scanner panels look like half the world is
# hostile, which is the wrong intuition to build a dashboard around.
CORPUS_MIX = [
    ("clean-text.eml", 55),
    ("clean-html.eml", 30),
    ("spam-gtube.eml", 10),
    ("virus-eicar.eml", 5),
]


def load_corpus():
    """Read the corpus once. Re-reading per message would measure the disk."""
    messages = {}
    for name, _ in CORPUS_MIX:
        path = os.path.join(CORPUS_DIR, name)
        if not os.path.exists(path):
            sys.exit(f"corpus file missing: {path}")
        with open(path, "rb") as handle:
            raw = handle.read()
        # The corpus is stored the way any text file in git is, with bare LF.
        # SMTP requires CRLF, and this server enforces it — sending the files
        # verbatim gets every one of them refused with "bare LF not allowed",
        # which measures the line endings rather than the server. swaks
        # normalises quietly, which is why the existing corpus script does not
        # hit this.
        messages[name] = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return messages


REPLACED_HEADERS = (b"message-id:", b"date:", b"x-elemta-stress-")


def strip_headers(raw):
    """Remove the headers this script is about to supply.

    Prepending Message-ID to a corpus file that already has one produces a
    message with two of them, which RFC 5322 forbids and which the server
    resolves by keeping the corpus value. The visible symptom is that 900
    messages share four message ids, so nothing downstream can tell them
    apart — every per-message panel and every trace collapses to one of four
    rows. Continuation lines are dropped with their header, or the folded
    remainder of a removed Date would be left behind as a bare line.
    """
    split = raw.find(b"\r\n\r\n")
    if split == -1:  # headers only, or not a well-formed message
        head, body = raw, b""
    else:
        head, body = raw[:split + 2], raw[split + 2:]

    kept, skipping = [], False
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t"):
            if not skipping:
                kept.append(line)
            continue
        skipping = line.lower().startswith(REPLACED_HEADERS)
        if not skipping:
            kept.append(line)
    return b"\r\n".join(kept), body


def build_message(raw, name, run_id, sequence):
    """Stamp a message so a dashboard can find this run and this kind."""
    head, body = strip_headers(raw)
    headers = (
        f"X-Elemta-Stress-Run: {run_id}\r\n"
        f"X-Elemta-Stress-Kind: {name}\r\n"
        f"Message-ID: <stress-{run_id}-{sequence}@stress.example.com>\r\n"
        f"Date: {email.utils.formatdate(localtime=True)}\r\n"
    ).encode()
    return headers + head + body


def worker(host, port, work, results, run_id, corpus, stop):
    while not stop.is_set():
        try:
            sequence, name = work.get_nowait()
        except queue.Empty:
            return

        started = time.monotonic()
        outcome = "accepted"
        detail = ""
        try:
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                smtp.ehlo("stress.example.com")
                smtp.sendmail(
                    "stress@stress.example.com",
                    ["user@example.com"],
                    build_message(corpus[name], name, run_id, sequence),
                )
        except smtplib.SMTPResponseException as exc:
            # A refusal is a result, not an error: the corpus contains samples
            # a correctly configured server may well reject.
            outcome = "rejected"
            detail = f"{exc.smtp_code} {exc.smtp_error!r}"
        except Exception as exc:  # noqa: BLE001 - any failure is worth counting
            outcome = "error"
            detail = str(exc)

        results.put((name, outcome, time.monotonic() - started, detail))
        work.task_done()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--messages", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--run-id", default=None,
                        help="Defaults to a random id; set it to group several runs")
    args = parser.parse_args()

    run_id = args.run_id or uuid.uuid4().hex[:8]
    corpus = load_corpus()

    names = [name for name, _ in CORPUS_MIX]
    weights = [weight for _, weight in CORPUS_MIX]
    work = queue.Queue()
    for sequence in range(args.messages):
        work.put((sequence, random.choices(names, weights=weights)[0]))

    results = queue.Queue()
    stop = threading.Event()
    threads = [
        threading.Thread(target=worker,
                         args=(args.host, args.port, work, results, run_id, corpus, stop),
                         daemon=True)
        for _ in range(args.concurrency)
    ]

    print(f"run {run_id}: {args.messages} messages, {args.concurrency} concurrent, "
          f"to {args.host}:{args.port}")
    # monotonic for the duration, wall clock for the dashboard link: the two
    # clocks answer different questions and monotonic has no calendar.
    started = time.monotonic()
    wall_started = time.time()
    for thread in threads:
        thread.start()
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        stop.set()
        print("\ninterrupted; reporting what finished")
    elapsed = time.monotonic() - started

    outcomes = Counter()
    by_kind = Counter()
    latencies = []
    details = Counter()
    while not results.empty():
        name, outcome, latency, detail = results.get()
        outcomes[outcome] += 1
        by_kind[(name, outcome)] += 1
        latencies.append(latency)
        if detail:
            details[detail[:80]] += 1

    total = sum(outcomes.values())
    print(f"\n{total} sent in {elapsed:.1f}s "
          f"({total / elapsed:.1f}/s)" if elapsed > 0 else "")
    for outcome, count in outcomes.most_common():
        print(f"  {outcome:10} {count}")
    print("\nby message kind:")
    for (name, outcome), count in sorted(by_kind.items()):
        print(f"  {name:18} {outcome:10} {count}")
    if latencies:
        latencies.sort()
        def pct(p):
            return latencies[min(len(latencies) - 1, int(len(latencies) * p))]
        print(f"\nlatency  p50 {pct(0.50)*1000:.0f}ms  "
              f"p95 {pct(0.95)*1000:.0f}ms  max {latencies[-1]*1000:.0f}ms")
    if details:
        print("\nresponses:")
        for detail, count in details.most_common(5):
            print(f"  {count:5}  {detail}")

    # A run is found on the dashboard by when it happened, not by its id: the
    # stress headers travel with the message but nothing logs them, so telling
    # anyone to filter on X-Elemta-Stress-Run would be advice that silently
    # matches zero documents. The time range is both true and precise.
    window = kibana_link(wall_started, time.time())
    print(f"\nThis run on the dashboard:\n  {window}")
    return 0 if outcomes["error"] == 0 else 1


def kibana_link(started, ended, base="http://localhost:5601"):
    """A dashboard URL pinned to exactly this run, with a little padding so the
    first and last messages are not sitting on the edge of the chart."""
    frm = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(started - 5))
    to = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ended + 5))
    return (f"{base}/app/dashboards#/view/elemta-overview"
            f"?_g=(time:(from:'{frm}',to:'{to}'))")


if __name__ == "__main__":
    sys.exit(main())
