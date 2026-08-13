#!/usr/bin/env python3
"""Measure delivery throughput: how fast the queue actually drains.

Acceptance rate and delivery rate are different numbers and only one of them is
usually the interesting one. A stress test that reports "150 messages/sec" is
reporting how fast the server said 250 OK, which a server can do while
delivering nothing. This measures the other end.

Method: fill the queue, stop sending, then watch the depth fall. Draining with
no inbound traffic isolates delivery from reception, and sampling the queue
directory rather than the log means the number does not depend on the log
shipper keeping up.

  python3 scripts/dev/bench_queue.py --messages 6000 --concurrency 40

Read the result against the two settings that cap it:

  [queue_processor] workers        concurrent deliveries
  max_connections_per_domain       concurrent deliveries *to one domain*

The corpus sends everything to one domain, so if max_connections_per_domain is
below workers, the surplus workers claim messages they cannot deliver and those
are deferred with retry backoff — which grows the queue and looks like the
server is falling behind rather than like a configured limit.
"""

import argparse
import subprocess
import sys
import time

CONTAINER = "elemta-node0"


def queue_depth():
    """Count files in the active queue. Cheap, and independent of the logs."""
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "sh", "-c", "ls /app/queue/active 2>/dev/null | wc -l"],
        capture_output=True, text=True, timeout=30)
    try:
        return int(out.stdout.strip())
    except ValueError:
        return -1


def setting(pattern):
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "sh", "-c",
         f"grep -m1 -E '{pattern}' /app/runtime-config/elemta.toml"],
        capture_output=True, text=True, timeout=30)
    return out.stdout.strip() or "(not set)"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--messages", type=int, default=6000,
                        help="How many to enqueue before measuring")
    parser.add_argument("--concurrency", type=int, default=40,
                        help="Sending concurrency while filling the queue")
    parser.add_argument("--sample", type=int, default=10, help="Seconds between depth samples")
    parser.add_argument("--max-wait", type=int, default=900,
                        help="Give up waiting for the queue to drain after this long")
    args = parser.parse_args()

    if queue_depth() < 0:
        sys.exit(f"Cannot read the queue in {CONTAINER}. Is the dev stack running?")

    print("settings that cap delivery:")
    print(f"  {setting('^workers')}")
    print(f"  {setting('^max_connections_per_domain')}")
    print(f"  {setting('^interval')}\n")

    start_depth = queue_depth()
    if start_depth > 50:
        print(f"note: {start_depth} messages already queued; the measurement "
              f"includes draining those.\n")

    print(f"filling: {args.messages} messages at concurrency {args.concurrency}")
    subprocess.run([sys.executable, "scripts/dev/stress_corpus.py",
                    "--messages", str(args.messages),
                    "--concurrency", str(args.concurrency)],
                   capture_output=True, text=True)

    peak = queue_depth()
    print(f"queued: {peak} messages. Sending stopped; measuring drain.\n")

    samples = []
    began = time.time()
    previous, last_change = peak, time.time()
    # When the queue last actually moved, and how much was left then. The
    # headline rate is measured to this point, not to when the script gave up:
    # a handful of messages that will never deliver would otherwise drag the
    # average down by several times and make a healthy server look slow.
    drain_end, drain_depth = began, peak
    while time.time() - began < args.max_wait:
        time.sleep(args.sample)
        depth = queue_depth()
        elapsed = time.time() - began
        rate = (previous - depth) / args.sample
        samples.append(rate)
        print(f"  {elapsed:6.0f}s  depth={depth:7}  {rate:8.1f}/s")
        if depth < previous:
            drain_end, drain_depth = time.time(), depth
        if depth != previous:
            previous, last_change = depth, time.time()
        if depth <= 5:
            break
        # A queue that stops moving is not draining slowly, it is stuck.
        if time.time() - last_change > 120:
            print("\n  depth has not changed for two minutes — deliveries are "
                  "failing or deferring, not running slowly.")
            print("  Check: docker logs elemta-node0 | grep deferral_reason")
            break

    residue = queue_depth()
    drained = peak - drain_depth
    window = drain_end - began
    print(f"\n  drained {drained} of {peak} in {window:.0f}s")
    if window > 0 and drained > 0:
        print(f"  average {drained / window:.1f}/s   (over the draining window,"
              f" excluding any stalled tail)")
    moving = [r for r in samples if r > 0]
    if moving:
        print(f"  peak    {max(moving):.1f}/s")
    if residue > 5:
        print(f"\n  {residue} messages never drained. Those are stuck, not slow —"
              f" they are not counted in the rate above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
