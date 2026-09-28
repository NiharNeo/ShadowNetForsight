"""Authenticated recovery snapshots. Pause profile changes during backup; restore offline."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.security import SecurityManager


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def safe_file(root: Path, name: str) -> Path:
    parts = PurePosixPath(name).parts
    if not parts or PurePosixPath(name).is_absolute() or '..' in parts or '\\' in name:
        raise ValueError('Invalid snapshot path')
    path = root.joinpath(*parts)
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('Snapshot symlinks are not supported')
    return path


def validate_database(path: Path, secret: str) -> dict:
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    try:
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Database integrity check failed')
        for table in ('users', 'audit_log', 'login_attempts'):
            connection.execute(f'SELECT 1 FROM {table} LIMIT 1')
    finally:
        connection.close()
    result = SecurityManager(path, secret).verify_audit_chain()
    if not result['valid']:
        raise ValueError('Audit chain verification failed')
    return result


def publish(staging: Path, destination: Path) -> None:
    # Reserve the destination without overwriting an existing recovery directory.
    destination.mkdir(mode=0o700)
    try:
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(destination)
        raise


def backup(source: Path, destination: Path, secret: str) -> dict:
    source, destination = source.resolve(), destination.absolute()
    if not secret:
        raise ValueError('Original SHADOWNET_TOKEN_SECRET is required')
    if destination.exists():
        raise FileExistsError('Snapshot destination already exists')
    database = safe_file(source, 'shadownet.db')
    if not database.is_file():
        raise ValueError('Source database does not exist')
    with tempfile.TemporaryDirectory(prefix='.shadownet-backup-', dir=destination.parent) as temporary:
        stage = Path(temporary)
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
        target = sqlite3.connect(stage / 'shadownet.db')
        try:
            connection.backup(target)
        finally:
            target.close()
            connection.close()
        audit = validate_database(stage / 'shadownet.db', secret)
        names = ['shadownet.db']
        profiles = safe_file(source, 'calibrations')
        if profiles.exists():
            for profile in sorted(profiles.glob('*.json')):
                name = 'calibrations/' + profile.name
                src = safe_file(source, name)
                json.loads(src.read_text())
                out = stage / name
                out.parent.mkdir(exist_ok=True, mode=0o700)
                shutil.copyfile(src, out)
                names.append(name)
        for name in names:
            (stage / name).chmod(0o600)
        manifest = {'version': 1, 'files': {name: digest(stage / name) for name in names},
                    'audit_entries': audit['entries']}
        envelope = {'manifest': manifest, 'signature': hmac.new(secret.encode(), canonical(manifest), hashlib.sha256).hexdigest()}
        (stage / 'manifest.json').write_text(json.dumps(envelope, indent=2) + '\n')
        (stage / 'manifest.json').chmod(0o600)
        publish(stage, destination)
    return {'snapshot': str(destination), 'files': len(names), 'audit_entries': audit['entries']}


def restore(source: Path, destination: Path, secret: str) -> dict:
    source, destination = source.resolve(), destination.absolute()
    if not secret:
        raise ValueError('Original SHADOWNET_TOKEN_SECRET is required')
    if destination.exists():
        raise FileExistsError('Restore destination must not exist')
    envelope = json.loads(safe_file(source, 'manifest.json').read_text())
    manifest = envelope['manifest']
    expected = hmac.new(secret.encode(), canonical(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(envelope['signature'], expected):
        raise ValueError('Snapshot signature mismatch: wrong secret or modified manifest')
    if manifest['version'] != 1 or 'shadownet.db' not in manifest['files']:
        raise ValueError('Unsupported snapshot manifest')
    with tempfile.TemporaryDirectory(prefix='.shadownet-restore-', dir=destination.parent) as temporary:
        stage = Path(temporary)
        for name, expected_digest in manifest['files'].items():
            if name != 'shadownet.db' and not (name.startswith('calibrations/') and len(PurePosixPath(name).parts) == 2 and name.endswith('.json')):
                raise ValueError('Unexpected recovery file')
            src, target = safe_file(source, name), safe_file(stage, name)
            target.parent.mkdir(exist_ok=True, mode=0o700)
            shutil.copyfile(src, target)
            target.chmod(0o600)
            if not hmac.compare_digest(digest(target), expected_digest):
                raise ValueError('Snapshot file checksum mismatch')
        audit = validate_database(stage / 'shadownet.db', secret)
        if audit['entries'] != manifest['audit_entries']:
            raise ValueError('Snapshot audit count mismatch')
        publish(stage, destination)
    return {'restored': str(destination), 'files': len(manifest['files']), 'audit_entries': audit['entries']}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('backup', 'restore'))
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = (backup if args.action == 'backup' else restore)(args.source, args.destination, os.getenv('SHADOWNET_TOKEN_SECRET', ''))
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        parser.exit(1, f'Recovery operation failed: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
