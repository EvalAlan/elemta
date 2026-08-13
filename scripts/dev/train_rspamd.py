#!/usr/bin/env python3
"""Train Rspamd's Bayes classifier from a labelled corpus, and measure it.

The dev Rspamd ships with no statistical filter, so the spam score is a sum of
infrastructure penalties — unknown HELO hostname, missing Message-ID, missing
or past Date, no SPF or DKIM. Those punish replayed corpus mail rather than
spam, which is how this stack came to score real Enron ham above real spam.

Training alone is not the point; knowing whether it worked is. So this scores a
held-out sample before and after, and the messages it trains on are never the
messages it measures on. A classifier evaluated on its own training set will
report near-perfect accuracy no matter how badly it generalises, which is the
most comfortable way to be wrong about a spam filter.

  python3 scripts/dev/train_rspamd.py \\
      --ham-dir  /mnt/data/email-corpus/enron/extracted/maildir \\
      --spam-dir /mnt/data/email-corpus/untroubled/extracted \\
      --train 2000 --test 200
"""

import argparse
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile

CONTAINER = "elemta-rspamd"
# Rspamd's own default: Bayes stays silent until it has seen this many of each
# class. Training fewer and then wondering why BAYES_* never fires is a
# well-worn hole.
MIN_LEARNS = 200


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def container_running():
    out = run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split()
    return CONTAINER in out


def collect(directory, limit, seed):
    """Sample files deterministically, so train and test stay disjoint across
    runs and a re-run reproduces the same split."""
    paths = []
    for root, _, names in os.walk(directory):
        for name in names:
            path = os.path.join(root, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            # Skip archives and empty files: the untroubled corpus ships .7z
            # next to its extracted messages, and feeding an archive to a
            # Bayes classifier teaches it about compression.
            if size == 0 or size > 1_000_000:
                continue
            if name.endswith((".7z", ".gz", ".bz2", ".zip", ".tar")):
                continue
            paths.append(path)
    paths.sort()
    random.Random(seed).shuffle(paths)
    return paths[:limit]


def stage(paths, prefix):
    """Copy a sample into the container under one directory.

    rspamc reads paths in its own filesystem, and the corpus lives on the host.
    Copying a batch and pointing rspamc at the directory is far faster than one
    exec per message.
    """
    local = tempfile.mkdtemp(prefix=f"rspamd-{prefix}-")
    for index, path in enumerate(paths):
        try:
            shutil.copyfile(path, os.path.join(local, f"{prefix}{index:06d}.eml"))
        except OSError:
            continue
    remote = f"/tmp/{prefix}"
    run(["docker", "exec", CONTAINER, "rm", "-rf", remote])
    run(["docker", "exec", CONTAINER, "mkdir", "-p", remote])
    result = run(["docker", "cp", f"{local}/.", f"{CONTAINER}:{remote}/"])
    if result.returncode != 0:
        sys.exit(f"copying {prefix} into {CONTAINER} failed: {result.stderr.strip()}")
    shutil.rmtree(local, ignore_errors=True)
    return remote


def score_dir(remote):
    """Score every message in a container directory, returning the scores.

    One shell loop inside a single exec: a docker exec per message turns a
    200-message evaluation into minutes of process startup.
    """
    script = (
        f'for f in {remote}/*; do '
        f'rspamc symbols "$f" 2>/dev/null | sed -n "s|^Score: \\([0-9.-]*\\).*|\\1|p" | head -1; '
        f'done'
    )
    out = run(["docker", "exec", CONTAINER, "sh", "-c", script]).stdout
    return [float(line) for line in out.split() if line.replace(".", "").replace("-", "").isdigit()]


def learn(remote, spam):
    command = "learn_spam" if spam else "learn_ham"
    result = run(["docker", "exec", CONTAINER, "sh", "-c",
                  f'rspamc {command} {remote} 2>&1 | grep -c "success = true"'])
    return int(result.stdout.strip() or 0)


def describe(name, scores):
    if not scores:
        return f"  {name:16} (no scores)"
    ordered = sorted(scores)
    return (f"  {name:16} n={len(ordered):4}  median={statistics.median(ordered):6.2f}  "
            f"p75={ordered[3 * len(ordered) // 4]:6.2f}  max={ordered[-1]:6.2f}")


def report(ham, spam, thresholds):
    print(describe("ham", ham))
    print(describe("spam", spam))
    if not ham or not spam:
        return
    print()
    print(f"  {'threshold':>10}  {'spam caught':>14}  {'ham flagged':>14}")
    for threshold in thresholds:
        caught = sum(1 for value in spam if value >= threshold)
        flagged = sum(1 for value in ham if value >= threshold)
        print(f"  {threshold:>10.1f}  {caught:5}/{len(spam):<4} {100 * caught / len(spam):5.1f}%  "
              f"{flagged:5}/{len(ham):<4} {100 * flagged / len(ham):5.1f}%")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ham-dir", required=True)
    parser.add_argument("--spam-dir", required=True)
    parser.add_argument("--train", type=int, default=2000, help="Messages per class to learn")
    parser.add_argument("--test", type=int, default=200, help="Held-out messages per class")
    parser.add_argument("--seed", type=int, default=1734)
    parser.add_argument("--thresholds", default="6,8,10,12,15")
    args = parser.parse_args()

    if not container_running():
        sys.exit(f"{CONTAINER} is not running. Start the dev stack first.")
    if args.train < MIN_LEARNS:
        print(f"⚠️  Training on {args.train} per class, below Rspamd's min_learns "
              f"of {MIN_LEARNS}. Bayes will stay silent.", file=sys.stderr)

    thresholds = [float(x) for x in args.thresholds.split(",")]
    total = args.train + args.test

    for label, directory in (("ham", args.ham_dir), ("spam", args.spam_dir)):
        if not os.path.isdir(directory):
            sys.exit(f"{label} directory does not exist: {directory}")

    ham_all = collect(args.ham_dir, total, args.seed)
    spam_all = collect(args.spam_dir, total, args.seed + 1)
    for label, found in (("ham", ham_all), ("spam", spam_all)):
        if len(found) < total:
            print(f"⚠️  only {len(found)} {label} messages available, wanted {total}",
                  file=sys.stderr)
    if min(len(ham_all), len(spam_all)) <= args.test:
        sys.exit("not enough messages to split into training and held-out sets")

    # The split. Held-out messages are taken from the end of the sample and
    # trained messages from the start.
    #
    # Which end is arbitrary for a single run, but it keeps repeat runs honest:
    # the sample order is fixed by the seed, so growing --train extends the
    # training set forwards while the held-out tail moves further away from it.
    # Taking the held-out set from the front instead would mean a larger --test
    # silently absorbs messages an earlier, smaller run had already trained on,
    # and the classifier would be measured on messages it had memorised.
    ham_test, ham_train = ham_all[-args.test:], ham_all[:-args.test]
    spam_test, spam_train = spam_all[-args.test:], spam_all[:-args.test]
    print(f"train: {len(ham_train)} ham / {len(spam_train)} spam    "
          f"held-out: {len(ham_test)} ham / {len(spam_test)} spam    seed {args.seed}\n")

    ham_test_dir = stage(ham_test, "testham")
    spam_test_dir = stage(spam_test, "testspam")

    print("BEFORE training")
    before_ham = score_dir(ham_test_dir)
    before_spam = score_dir(spam_test_dir)
    report(before_ham, before_spam, thresholds)

    print("\nlearning...")
    learned_ham = learn(stage(ham_train, "trainham"), spam=False)
    learned_spam = learn(stage(spam_train, "trainspam"), spam=True)
    print(f"  learned {learned_ham} ham, {learned_spam} spam")

    print("\nAFTER training")
    after_ham = score_dir(ham_test_dir)
    after_spam = score_dir(spam_test_dir)
    report(after_ham, after_spam, thresholds)

    if before_ham and after_ham and before_spam and after_spam:
        gap_before = statistics.median(before_spam) - statistics.median(before_ham)
        gap_after = statistics.median(after_spam) - statistics.median(after_ham)
        print(f"\nseparation (median spam - median ham): "
              f"{gap_before:+.2f} -> {gap_after:+.2f}")
        if gap_after <= 0:
            print("Still inverted: ham scores at least as high as spam. Do not enable "
                  "reject_on_spam.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
