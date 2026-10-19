#!/usr/bin/env python3
"""Bounded SMTP, IMAP and webmail stress runs against an explicitly named dev host."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import email.utils
import getpass
import html
import http.cookiejar
import imaplib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import smtplib
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid


PROFILES = {
    'smoke': {'smtp': [(1, 20, 16384), (4, 80, 16384), (4, 8, 524288)],
              'imap': [(4, 3)], 'webmail': [(2, 3)]},
    'ramp': {'smtp': [(1, 100, 16384), (4, 400, 16384), (8, 800, 16384), (4, 32, 524288)],
             'imap': [(4, 10), (16, 10), (32, 5)], 'webmail': [(4, 10)]},
}

# Only aggregate metrics are returned; resolved Compose config and environment
# values would expose credentials in the report.
HOST_SAMPLE = r'''
import json,os,re,subprocess,time,urllib.request
mem={line.split(':')[0]:int(line.split()[1])*1024 for line in open('/proc/meminfo')}
disk=os.statvfs('/')
metrics=urllib.request.urlopen('http://127.0.0.1:9080/metrics',timeout=5).read().decode()
queue={q:float(n) for q,n in re.findall(r'elemta_queue_size\{queue_type="([^"]+)"\} ([0-9.eE+-]+)',metrics)}
if not queue: raise RuntimeError('queue metrics unavailable')
names=subprocess.check_output(['docker','ps','-a','--filter','name=elemta-','--format','{{.Names}}'],text=True).split()
containers=[]
for name in names:
    raw=subprocess.check_output(['docker','inspect','--format','{"name":"{{.Name}}","running":{{.State.Running}},"oom":{{.State.OOMKilled}},"restarts":{{.RestartCount}},"health":"{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}","image":"{{.Image}}"}',name],text=True)
    item=json.loads(raw); item['name']=item['name'].lstrip('/'); containers.append(item)
stats=subprocess.check_output(['docker','stats','--no-stream','--format','{{json .}}',*names],text=True)
print(json.dumps({'time':time.time(),'load':os.getloadavg(),'available_bytes':mem['MemAvailable'],
 'swap_used_bytes':mem['SwapTotal']-mem['SwapFree'],'disk_free_bytes':disk.f_bavail*disk.f_frsize,
 'queue':queue,'containers':containers,'docker_stats':[json.loads(line) for line in stats.splitlines()]}))
'''


def distribution(values):
    ordered = sorted(values)
    if not ordered:
        return {'count': 0}
    return {'count': len(ordered), 'mean_ms': sum(ordered) / len(ordered),
            **{f'p{p}_ms': ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)] for p in (50, 95, 99)}}


class Runner:
    def __init__(self, args):
        self.args = args
        self.ctx = ssl.create_default_context()
        self.stop = threading.Event()
        self.run_id = 'stress-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
        self.address = self.run_id + '@' + args.domain
        self.password = secrets.token_urlsafe(32)
        self.root = Path(__file__).resolve().parents[2]
        self.output = Path(args.output_root).resolve() / self.run_id
        if self.output.is_relative_to(self.root):
            relative = str(self.output.relative_to(self.root)) + '/report.json'
            if subprocess.run(['git', 'check-ignore', '-q', relative], cwd=self.root).returncode:
                raise RuntimeError('Reports inside the checkout must be ignored by Git')
        self.output.mkdir(parents=True, mode=0o700)
        self.report = {'run': self.run_id, 'host': args.host, 'domain': args.domain,
                       'profile': args.profile, 'stages': [], 'samples': [], 'errors': [],
                       'scope': 'Authenticated local delivery, IMAP reads, webmail HTTP; no external recipients'}
        self.created = False
        self.baseline = None

    def write_json(self, name, value):
        path = self.output / name
        with path.open('w') as handle:
            json.dump(value, handle, indent=2)
            handle.write('\n')
        path.chmod(0o600)

    def remote(self, command, data=None):
        result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                                 self.args.ssh_user + '@' + self.args.host, shlex.join(command)],
                                input=data, text=True, capture_output=True, timeout=45)
        if result.returncode:
            raise RuntimeError('Remote operation failed: ' + (result.stderr or result.stdout)[-1000:])
        return result.stdout

    def provision(self, *args, data=None):
        return self.remote(['docker', 'exec', '-i', 'elemta-web', '/app/elemta', '-c',
                            '/app/runtime-config/elemta.toml', 'provision', *args], data)

    def sample(self):
        sample = json.loads(self.remote(['python3', '-'], HOST_SAMPLE))
        self.report['samples'].append(sample)
        self.write_json('report.json', self.report)
        if sample['available_bytes'] < 256 * 1024**2 or sample['disk_free_bytes'] < 5 * 1024**3:
            raise RuntimeError('Stopped at memory or disk headroom limit')
        if sum(sample['queue'].get(k, 0) for k in ('active', 'deferred')) > 2000:
            raise RuntimeError('Stopped at queue backlog limit')
        if self.baseline:
            original = {c['name']: c for c in self.baseline['containers'] if c['running']}
            current = {c['name']: c for c in sample['containers']}
            for name, old in original.items():
                new = current.get(name, {})
                if not new.get('running') or new.get('health') == 'unhealthy' or new.get('oom') or new.get('restarts', 0) > old['restarts']:
                    raise RuntimeError('Service stopped, restarted, became unhealthy or hit OOM: ' + name)
            if sample['queue'].get('failed', 0) > self.baseline['queue'].get('failed', 0):
                raise RuntimeError('Failed queue grew during stress run')
        return sample

    def imap(self):
        client = imaplib.IMAP4_SSL(self.args.host, 993, ssl_context=self.ctx, timeout=20)
        try:
            client.login(self.address, self.password)
            return client
        except BaseException:
            client.shutdown()
            raise

    @staticmethod
    def ok(response):
        if response[0] != 'OK':
            raise RuntimeError('IMAP operation failed: ' + str(response[0]))
        return response[1]

    def smtp_stage(self, concurrency, count, size, number):
        stage = f'smtp-{number}'
        lock = threading.Lock()
        latencies, errors = [], []
        accepted = 0
        body = (b'Ordinary local delivery stress payload.\r\n' * (size // 40 + 2))[:size - 2].rstrip(b'\r\n') + b'\r\n'
        began = time.monotonic()
        record = {'kind': 'smtp', 'stage': stage, 'concurrency': concurrency,
                  'requested': count, 'body_bytes': len(body)}
        self.report['stages'].append(record)

        def worker(index):
            nonlocal accepted
            try:
                with smtplib.SMTP(self.args.host, 587, timeout=20) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=self.ctx)
                    smtp.ehlo()
                    smtp.login(self.address, self.password)
                    for seq in range(index, count, concurrency):
                        if self.stop.is_set():
                            break
                        head = (f'From: {self.address}\r\nTo: {self.address}\r\nDate: {email.utils.formatdate()}\r\n'
                                f'Subject: {self.run_id} {stage} {seq}\r\n'
                                f'Message-ID: <{stage}-{seq}.{self.run_id}@{self.args.domain}>\r\n'
                                f'X-Elemta-Stress-Stage: {stage}\r\nMIME-Version: 1.0\r\n'
                                'Content-Type: text/plain; charset=utf-8\r\n\r\n').encode()
                        start = time.monotonic()
                        refused = smtp.sendmail(self.address, [self.address], head + body)
                        if refused:
                            raise RuntimeError('SMTP recipient refused')
                        with lock:
                            accepted += 1
                            latencies.append((time.monotonic() - start) * 1000)
            except Exception as exc:
                with lock:
                    errors.append(type(exc).__name__ + ': ' + str(exc)[:240])
                self.stop.set()

        print(f'{stage}: {count} messages, {concurrency} SMTP clients, {size // 1024} KiB bodies', flush=True)
        delivered, peak_queue, last_sample = 0, 0, 0
        with self.imap() as observer, ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(worker, i) for i in range(concurrency)]
            while True:
                self.ok(observer.select('INBOX', readonly=True))
                data = self.ok(observer.uid('search', None, 'HEADER', 'X-Elemta-Stress-Stage', stage))
                delivered = len(data[0].split())
                done = all(f.done() for f in futures)
                if done and (self.stop.is_set() or delivered == accepted):
                    break
                if time.monotonic() - began > self.args.phase_timeout:
                    self.stop.set()
                    errors.append('Phase deadline exceeded')
                    break
                if time.monotonic() - last_sample >= 5:
                    try:
                        sample = self.sample()
                        peak_queue = max(peak_queue, sum(sample['queue'].get(k, 0) for k in ('active', 'deferred')))
                    except Exception:
                        self.stop.set()
                        raise
                    last_sample = time.monotonic()
                time.sleep(0.5)
            for future in futures:
                future.result()
            if not errors and delivered == count:
                ids = data[0].split()
                message_ids = []
                for offset in range(0, len(ids), 200):
                    fetched = self.ok(observer.uid('fetch', b','.join(ids[offset:offset + 200]).decode(), '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])'))
                    message_ids.extend(email.message_from_bytes(item[1]).get('Message-ID') for item in fetched if isinstance(item, tuple))
                expected = {f'<{stage}-{i}.{self.run_id}@{self.args.domain}>' for i in range(count)}
                if len(message_ids) != count or set(message_ids) != expected:
                    errors.append('Delivered Message-IDs contain missing or duplicated fixtures')
        elapsed = time.monotonic() - began
        record.update(accepted=accepted, delivered=delivered, elapsed_seconds=elapsed,
                      delivered_per_second=delivered / elapsed, smtp_data_latency=distribution(latencies),
                      peak_queue=peak_queue, errors=errors)
        print(f'  accepted={accepted} delivered={delivered} elapsed={elapsed:.2f}s delivery={delivered / elapsed:.2f}/s '
              f'DATA p95={record["smtp_data_latency"].get("p95_ms", 0):.1f}ms', flush=True)
        if errors or accepted != count or delivered != count:
            raise RuntimeError('SMTP stage did not deliver every requested message exactly once')
        self.sample()

    def read_stage(self, kind, concurrency, iterations):
        latencies, errors = [], []
        lock = threading.Lock()
        began = time.monotonic()
        def worker(_):
            try:
                if kind == 'imap':
                    with self.imap() as client:
                        for _ in range(iterations):
                            if self.stop.is_set(): break
                            start = time.monotonic()
                            self.ok(client.select('INBOX', readonly=True))
                            ids = self.ok(client.uid('search', None, 'SUBJECT', self.run_id))[0].split()[-50:]
                            if not ids: raise RuntimeError('No delivered fixture messages found')
                            self.ok(client.uid('fetch', b','.join(ids).decode(), '(UID FLAGS ENVELOPE BODYSTRUCTURE)'))
                            with lock: latencies.append((time.monotonic() - start) * 1000)
                else:
                    cookies = http.cookiejar.CookieJar()
                    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx), urllib.request.HTTPCookieProcessor(cookies))
                    origin = 'https://' + self.args.host
                    with opener.open(origin + '/login', timeout=20) as response:
                        page = response.read().decode()
                    token = html.unescape(re.search(r'name="token" value="([^"]+)"', page).group(1))
                    payload = urllib.parse.urlencode({'token': token, 'user': self.address, 'password': self.password}).encode()
                    request = urllib.request.Request(origin + '/login', data=payload, headers={'Origin': origin})
                    with opener.open(request, timeout=20) as response:
                        response.read()
                    if not any(c.name == 'elemta_wm' for c in cookies):
                        raise RuntimeError('Webmail login did not create an authenticated session')
                    for _ in range(iterations):
                        if self.stop.is_set(): break
                        for path in ('/mail', '/api/counts'):
                            start = time.monotonic()
                            with opener.open(origin + path, timeout=20) as response:
                                if '/login' in response.geturl(): raise RuntimeError('Webmail session lost')
                                response.read()
                            with lock: latencies.append((time.monotonic() - start) * 1000)
            except Exception as exc:
                with lock: errors.append(type(exc).__name__ + ': ' + str(exc)[:240])
                self.stop.set()
        print(f'{kind}: {concurrency} clients, {iterations} iterations each', flush=True)
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(worker, i) for i in range(concurrency)]
            while not all(f.done() for f in futures):
                if time.monotonic() - began > self.args.phase_timeout:
                    self.stop.set()
                    raise RuntimeError(kind + ' phase deadline exceeded')
                try: self.sample()
                except Exception:
                    self.stop.set()
                    raise
                time.sleep(1)
            for future in futures: future.result()
        elapsed = time.monotonic() - began
        record = {'kind': kind, 'concurrency': concurrency, 'iterations': iterations,
                  'elapsed_seconds': elapsed, 'latency': distribution(latencies), 'errors': errors}
        self.report['stages'].append(record)
        print(f'  operations={len(latencies)} p95={record["latency"].get("p95_ms", 0):.1f}ms errors={len(errors)}', flush=True)
        if errors: raise RuntimeError(kind + ' phase failed')

    def run(self):
        success = False
        try:
            domains = self.provision('list-domains', '--json')
            domains = json.loads(domains[domains.index('['):])
            if not any(d['name'].lower() == self.args.domain and d['configured'] for d in domains):
                raise RuntimeError('Requested fixture domain is not a configured local domain')
            self.baseline = self.sample()
            if any(c['health'] == 'unhealthy' for c in self.baseline['containers'] if c['running']):
                raise RuntimeError('Baseline contains unhealthy services')
            self.provision('create-account', self.address, '--name', 'Temporary stress mailbox', '--quota', '512M', data=self.password + '\n')
            self.created = True
            self.write_json('fixture.json', {'address': self.address, 'password': self.password,
                                           'cleanup': 'Delete only this generated account after its queue has drained'})
            profile = PROFILES[self.args.profile]
            for number, stage in enumerate(profile['smtp'], 1): self.smtp_stage(*stage, number)
            for stage in profile['imap']: self.read_stage('imap', *stage)
            for stage in profile['webmail']: self.read_stage('webmail', *stage)
            self.sample()
            success = True
        except BaseException as exc:
            self.stop.set()
            self.report['errors'].append(type(exc).__name__ + ': ' + str(exc)[:1000])
            raise
        finally:
            self.report['passed'] = success
            if self.created and success:
                try:
                    with self.imap() as client:
                        self.ok(client.select('INBOX'))
                        ids = self.ok(client.uid('search', None, 'ALL'))[0]
                        if ids:
                            self.ok(client.uid('store', '1:*', '+FLAGS.SILENT', '(\\Deleted)'))
                            self.ok(client.expunge())
                    self.provision('delete-account', self.address, '--confirm', self.address)
                    self.write_json('fixture.json', {'address': self.address, 'deleted': True})
                    self.report['fixture_deleted'] = True
                except Exception as exc:
                    self.report['passed'] = False
                    self.report['errors'].append('Cleanup failed: ' + str(exc))
            elif self.created:
                self.report['fixture_preserved'] = True
                print('Run stopped; fixture preserved to avoid bouncing in-flight mail. Private credentials: ' + str(self.output / 'fixture.json'), flush=True)
            self.write_json('report.json', self.report)
            print('Private report: ' + str(self.output / 'report.json'), flush=True)
        return 0 if self.report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--domain', help='Must already be configured as a local domain; defaults to host')
    parser.add_argument('--ssh-user', default=getpass.getuser())
    parser.add_argument('--profile', choices=PROFILES, default='smoke')
    parser.add_argument('--output-root', default='.notes/stress-runs')
    parser.add_argument('--phase-timeout', type=int, default=180)
    args = parser.parse_args()
    args.domain = (args.domain or args.host).lower()
    for value in (args.host, args.domain):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', value): parser.error('Use a DNS hostname, without a URL or port')
    if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_-]*', args.ssh_user): parser.error('Invalid SSH user')
    if not 10 <= args.phase_timeout <= 900: parser.error('phase-timeout must be between 10 and 900 seconds')
    os.umask(0o077)
    runner = Runner(args)
    try:
        return runner.run()
    except (Exception, KeyboardInterrupt) as exc:
        print(type(exc).__name__ + ': ' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
