#!/usr/bin/env python3
"""An LMTP sink that accepts everything and stores nothing.

Benchmarking delivery against Dovecot measures Dovecot: maildir writes, index
updates and sieve, which cost around 100ms a message and saturate at roughly
70/s on this hardware. That is a fair number for "how fast can this stack
deliver to real mailboxes", and useless for "how fast can Elemta deliver".
This answers the second question by removing the mailbox.

It is deliberately not a mail server. It parses just enough LMTP to be a
credible peer, discards the body, and keeps a counter.

  python3 lmtp_sink.py --port 2525

The one detail that matters: after the end-of-data marker, LMTP sends **one
response per accepted recipient**, not the single response SMTP sends (RFC 2033
section 4.2). A sink that answers once looks fine for single-recipient mail and
desynchronises the moment a message has two, which is exactly the kind of bug
that shows up as an unreproducible stall under load.
"""

import argparse
import asyncio
import signal
import time

delivered = 0
started = time.monotonic()


async def handle(reader, writer):
    global delivered
    recipients = 0

    async def send(line):
        writer.write(line.encode() + b"\r\n")
        await writer.drain()

    try:
        await send("220 sink.elemta.test LMTP ready")
        while True:
            raw = await reader.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").strip()
            upper = line.upper()

            if upper.startswith("LHLO") or upper.startswith("EHLO"):
                # Multiline, terminated by a space rather than a hyphen. 8BITMIME
                # is advertised because the corpus contains it and a sender that
                # believes otherwise may re-encode, changing what is measured.
                writer.write(b"250-sink.elemta.test\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250 PIPELINING\r\n")
                await writer.drain()
                recipients = 0
            elif upper.startswith("MAIL FROM"):
                recipients = 0
                await send("250 2.1.0 sender ok")
            elif upper.startswith("RCPT TO"):
                recipients += 1
                await send("250 2.1.5 recipient ok")
            elif upper.startswith("DATA"):
                await send("354 end with <CR><LF>.<CR><LF>")
                # Read and drop the body. The dot-stuffing is not undone because
                # nothing here reads the content.
                while True:
                    chunk = await reader.readline()
                    if not chunk or chunk in (b".\r\n", b".\n"):
                        break
                # One response per recipient. See the module docstring.
                for _ in range(max(1, recipients)):
                    await send("250 2.0.0 accepted, discarded")
                delivered += max(1, recipients)
                recipients = 0
            elif upper.startswith("RSET"):
                recipients = 0
                await send("250 2.0.0 reset")
            elif upper.startswith("NOOP"):
                await send("250 2.0.0 ok")
            elif upper.startswith("QUIT"):
                await send("221 2.0.0 bye")
                return
            else:
                await send("500 5.5.2 not implemented")
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        return
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def report(every):
    """Print a rate periodically, so the sink can be ruled out as the
    bottleneck without instrumenting anything else."""
    last, last_at = 0, time.monotonic()
    while True:
        await asyncio.sleep(every)
        now = time.monotonic()
        rate = (delivered - last) / max(0.001, now - last_at)
        print(f"sink: {delivered} accepted total, {rate:.1f}/s over the last {every}s",
              flush=True)
        last, last_at = delivered, now


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--report-every", type=int, default=10)
    args = parser.parse_args()

    server = await asyncio.start_server(handle, args.host, args.port, backlog=512)
    print(f"sink: LMTP on {args.host}:{args.port}, accepting and discarding", flush=True)

    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
        except NotImplementedError:
            pass

    asyncio.create_task(report(args.report_every))
    async with server:
        await stop
    print(f"sink: stopping after {delivered} messages", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
