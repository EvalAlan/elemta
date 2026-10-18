#!/usr/bin/env python3
"""Export quiesced development Dovecot mail and metadata into a private snapshot.

Stop SMTP, webmail, and other mail clients before running. The script stops
Dovecot's network services, exports using doveadm, then stops the container and
copies its entire mail volume. A failure leaves it quiesced; restart explicitly.
"""
import argparse
import datetime
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--container', default='elemta-dovecot')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)

    def docker(*parts):
        return subprocess.check_output(['docker', *parts], text=True)

    def dove(*parts):
        return docker('exec', args.container, 'doveadm', *parts)

    docker('exec', args.container, 'sh', '-c',
           'cp /etc/dovecot/dovecot.conf /tmp/before-mailbox-export.conf && '
           "sed -i 's/^protocols =.*/protocols =/' /etc/dovecot/dovecot.conf")
    dove('reload')
    dove('kick', '*')
    manifest = {'accounts': []}
    for address in dove('user', '*').splitlines():
        status = json.loads(dove('-f', 'json', 'mailbox', 'status', '-u', address,
                                 'messages uidnext uidvalidity', '*'))
        subscribed = {v['mailbox'] for v in json.loads(dove('-f', 'json', 'mailbox', 'list', '-s', '-u', address))}
        messages = json.loads(dove('-f', 'json', 'fetch', '-u', address,
                                   'mailbox uid flags date.received storageid', 'all'))
        folders = []
        for entry in status:
            name = entry['mailbox']
            folder = {'name': name, 'uidvalidity': int(entry['uidvalidity']),
                      'uidnext': int(entry['uidnext']), 'subscribed': name in subscribed, 'messages': []}
            for msg in messages:
                if msg['mailbox'] != name:
                    continue
                # The mail volume is copied after shutdown. Resolve exact
                # current filenames afterward, including Maildir flag suffixes.
                folder['messages'].append({
                    'uid': int(msg['uid']), 'storageid': msg['storageid'],
                    'flags': [v for v in msg['flags'].split() if v.lower() != '\\recent'],
                    'date': datetime.datetime.strptime(msg['date.received'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc).isoformat()})
            folder['messages'].sort(key=lambda msg: msg['uid'])
            if len(folder['messages']) != int(entry['messages']):
                raise RuntimeError(f'{address}/{name}: export count changed')
            folders.append(folder)
        manifest['accounts'].append({'address': address, 'folders': folders})
    docker('exec', args.container, 'cp', '/tmp/before-mailbox-export.conf', '/etc/dovecot/dovecot.conf')
    docker('stop', args.container)
    subprocess.run(['docker', 'cp', f'{args.container}:/var/mail/.', str(output / 'mail')], check=True)
    for account in manifest['accounts']:
        for folder in account['folders']:
            base = output / 'mail' / account['address']
            if folder['name'] != 'INBOX':
                base /= '.' + folder['name'].replace('/', '.')
            files = {}
            for sub in ('cur', 'new'):
                if (base / sub).exists():
                    for path in (base / sub).iterdir():
                        key = path.name.split(':2,', 1)[0]
                        if key in files:
                            raise RuntimeError(f'duplicate Maildir filename: {path}')
                        files[key] = path
            for msg in folder['messages']:
                path = files[msg.pop('storageid')]
                msg['file'] = str(path.relative_to(output))
    (output / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    print(f"Exported {len(manifest['accounts'])} accounts, "
          f"{sum(len(f['messages']) for a in manifest['accounts'] for f in a['folders'])} messages to {output}")


if __name__ == '__main__':
    main()
