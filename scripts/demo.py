"""Prepare and start an isolated, reproducible local recording deployment."""
from pathlib import Path
import argparse
import json
import os
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ENV = ROOT / '.env.demo'
ACCESS = ROOT / 'data/demo/access.json'


def private_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)


def prepare():
    from scripts.generate_controlled_lab_pcaps import generate
    if not ENV.exists():
        private_write(ENV, 'SHADOWNET_TOKEN_SECRET=' + secrets.token_urlsafe(48) + '\nSHADOWNET_TRUSTED_HOSTS=localhost,127.0.0.1\n')
    if not ACCESS.exists():
        private_write(ACCESS, json.dumps({'username': 'techtrek-demo', 'password': secrets.token_urlsafe(18)}, indent=2) + '\n')
    destination = ROOT / 'data/demo/captures'
    manifest = generate(destination, duration_seconds=180)
    for capture in manifest['captures']:
        old = destination / capture['path']
        capture['path'] = capture['path'].replace('15m', '3m')
        old.replace(destination / capture['path'])
    (destination / 'pilot-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Demo capture files: {destination}\nPrivate login details: {ACCESS}\nDo not show login details in the recording.')


def compose(*args, **kwargs):
    subprocess.run(['docker', 'compose', '--env-file', str(ENV), '-p', 'shadownet-demo', '-f', str(ROOT / 'compose.yaml'), *args], cwd=ROOT, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'up', 'stop', 'status', 'seed'])
    args = parser.parse_args()
    if args.action == 'seed':
        from backend.security import SecurityManager
        payload = json.load(sys.stdin)
        manager = SecurityManager(Path(os.environ['SHADOWNET_DATA_DIR']) / 'shadownet.db')
        if not any(user['username'] == payload['username'] for user in manager.list_users()):
            manager.create_user(payload['username'], payload['password'], 'operator')
            manager.audit('demo-setup', 'CREATE_DEMO_USER', payload['username'], 201)
        print('Demo operator account ready')
    elif args.action == 'prepare':
        prepare()
    elif args.action == 'up':
        prepare()
        compose('up', '-d', '--build', '--wait', '--wait-timeout', '180')
        compose('exec', '-T', 'shadownet', 'python', '-m', 'scripts.demo', 'seed', input=ACCESS.read_text(), text=True)
        print('Demo ready: http://localhost:8000')
    elif args.action == 'stop':
        compose('stop')
    else:
        compose('ps')


if __name__ == '__main__':
    main()
