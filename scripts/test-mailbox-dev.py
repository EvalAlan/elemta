#!/usr/bin/env python3
"""Exercise the isolated mailbox Compose project without modifying source mailboxes."""
import argparse
import imaplib
import json
import os
from pathlib import Path
import smtplib
import subprocess
import time
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', default='user@example.com')
    parser.add_argument('--failover', action='store_true')
    parser.add_argument('--ha', action='store_true')
    parser.add_argument('--quorum-loss', action='store_true')
    args = parser.parse_args()
    password = os.environ['ELEMTA_TEST_MAILBOX_PASSWORD']
    root = Path(__file__).resolve().parent.parent
    imap_ports = (11445, 11446) if args.ha else (11443,)
    health_ports = (18035, 18036) if args.ha else (18031,)
    compose = ['docker', 'compose', '--env-file',
               str(root / 'deployments/compose/.secrets/mailbox-storage.env'),
               '-f', str(root / ('deployments/compose/docker-compose.mailbox-ha.yml' if args.ha else 'deployments/compose/docker-compose.mailbox.yml'))]
    token = 'mailbox-live-' + uuid.uuid4().hex
    folder = 'Check-' + uuid.uuid4().hex
    raw = (f'From: sender@example.com\r\nTo: {args.user}\r\n'
           f'Subject: {token}\r\nMessage-ID: <{token}@example.com>\r\n'
           'Content-Type: text/plain; charset=utf-8\r\n\r\n'
           'First line\r\n.\r\n..second\r\nLast line\r\n').encode()

    def connect():
        deadline = time.monotonic() + 35
        while True:
            try:
                client = imaplib.IMAP4('127.0.0.1', imap_ports[int(time.monotonic()) % len(imap_ports)], timeout=5)
                client.login(args.user, password)
                return client
            except (OSError, imaplib.IMAP4.error):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)

    def command(*arguments):
        subprocess.run(compose + list(arguments), check=True, stdout=subprocess.DEVNULL)

    def ready():
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{health_ports[int(time.monotonic()) % len(health_ports)]}/readyz', timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise RuntimeError('mailbox did not become ready')

    client = None
    try:
        ready()
        client = connect()
        assert client.create(folder)[0] == 'OK'
        client.select(folder)
        validity = client.response('UIDVALIDITY')[1]
        assert client.append(folder, None, None, raw)[0] == 'OK'
        client.select(folder)
        typ, data = client.uid('fetch', '1', '(BODY.PEEK[])')
        assert typ == 'OK' and any(isinstance(item, tuple) and item[1] == raw for item in data)
        assert client.uid('store', '1', '+FLAGS.SILENT', '(\\Flagged)')[0] == 'OK'
        client.logout()
        client = None

        # Stable internal queue IDs make a reconnect after an uncertain final safe.
        for _ in range(2):
            with smtplib.LMTP('127.0.0.1', 12426 if args.ha else 12424, timeout=15) as delivery:
                assert delivery.sendmail('sender@example.com', [args.user], raw,
                                         mail_options=['ENVID=' + token]) == {}
        client = connect()
        client.select('INBOX')
        typ, found = client.uid('search', None, 'HEADER', 'Subject', token)
        assert typ == 'OK' and len(found[0].split()) == 1
        client.logout()
        client = None

        if args.failover:
            # Connections can drop; reconnecting must retain UIDs, flags and bytes.
            for victim in ('mailbox-a', 'mailbox-b'):
                try:
                    command('stop', victim)
                    time.sleep(5)
                    ready()
                    client = connect()
                    assert client.select(folder)[0] == 'OK'
                    assert client.response('UIDVALIDITY')[1] == validity
                    typ, data = client.uid('fetch', '1', '(FLAGS BODY.PEEK[])')
                    assert typ == 'OK' and any(isinstance(item, tuple) and
                                              item[1] == raw and b'\\flagged' in item[0].lower()
                                              for item in data)
                    client.logout()
                    client = None
                finally:
                    command('start', victim)
                    time.sleep(5)
            if args.ha:
                cluster = json.loads(subprocess.check_output(compose + ['exec', '-T', 'pg-a', 'curl', '-fsS', 'http://localhost:8008/cluster']))
                leader = next(m['name'] for m in cluster['members'] if m['role'] == 'leader')
                # A hard stop tests loss without a cooperative switchover.
                command('stop', '-t', '0', leader)
                try:
                    started = time.monotonic()
                    ready()
                    client = connect()
                    assert client.select(folder)[0] == 'OK'
                    assert client.response('UIDVALIDITY')[1] == validity
                    assert client.uid('search', None, 'ALL')[1][0] == b'1'
                    assert client.append(folder, None, None, raw)[0] == 'OK'
                    client.logout()
                    client = None
                    print(f'Primary-loss recovery: {time.monotonic()-started:.1f}s')
                finally:
                    command('start', leader)
                # The alternate endpoint must work with the first edge gone.
                command('stop', 'edge-a')
                try:
                    ready()
                    client = connect()
                    assert client.select(folder)[0] == 'OK'
                    client.logout()
                    client = None
                finally:
                    command('start', 'edge-a')
                if args.quorum_loss:
                    client = connect()
                    client.select(folder)
                    command('stop', 'etcd-a')
                    try:
                        # One voter may fail without losing write availability.
                        assert client.append(folder, None, None, raw)[0] == 'OK'
                        command('stop', 'etcd-b')
                        try:
                            time.sleep(30)
                            accepted = False
                            try:
                                accepted = client.append(folder, None, None, raw)[0] == 'OK'
                            except (OSError, imaplib.IMAP4.error):
                                pass
                            assert not accepted, 'write acknowledged after coordination quorum loss'
                        finally:
                            command('start', 'etcd-b')
                    finally:
                        command('start', 'etcd-a')
                        try:
                            client.logout()
                        except (OSError, imaplib.IMAP4.error):
                            pass
                        client = None
                    ready()
                    print('PASS: one coordination voter can fail; quorum loss fences writes')
            else:
                command('restart', 'metadata')
            ready()
            client = connect()
            client.select(folder)
            assert client.response('UIDVALIDITY')[1] == validity
            assert client.uid('search', None, 'ALL')[1][0] == (b'1 2 3' if args.ha and args.quorum_loss else b'1 2' if args.ha else b'1')
            client.logout()
            client = None
        print('PASS: LDAP login, IMAP exact bytes/flags, LMTP retry deduplication' +
              (', replica loss/reconnect and ' + ('primary/edge failover' if args.ha else 'database restart') if args.failover else ''))
    finally:
        if client is not None:
            try:
                client.logout()
            except (OSError, imaplib.IMAP4.error):
                pass
        try:
            cleanup = connect()
            cleanup.delete(folder)
            cleanup.select('INBOX')
            typ, found = cleanup.uid('search', None, 'HEADER', 'Subject', token)
            if typ == 'OK' and found[0]:
                cleanup.uid('store', found[0].replace(b' ', b','), '+FLAGS.SILENT', '(\\Deleted)')
                cleanup.uid('expunge', found[0].replace(b' ', b','))
            cleanup.logout()
        except (OSError, imaplib.IMAP4.error):
            print('Fixture cleanup incomplete; inspect the isolated mailbox project.')


if __name__ == '__main__':
    main()
