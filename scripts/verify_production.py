"""Isolated production-mode smoke check. Never touches the deployed data directory."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from backend.security import SecurityManager
from scripts.manage_backup import backup, restore
from scripts.generate_controlled_lab_pcaps import generate

EXPECTED_CHECKPOINT = 'c8011213c29902a2c7c0fe34e1e1cdf0ba03e8dfdd7dc70477f1b08687531d48'


def verify(port: int) -> dict:
    checkpoint = ROOT / 'models/cic2018-phase1-lstm/lstm.pt'
    if hashlib.sha256(checkpoint.read_bytes()).hexdigest() != EXPECTED_CHECKPOINT:
        raise RuntimeError('Unexpected checkpoint. Review and approve the new release first.')
    report = {'scope': 'isolated production-mode smoke; not a capacity certification', 'checks': {}}
    with tempfile.TemporaryDirectory(prefix='shadownet-release-') as directory:
        data = Path(directory)
        secret, password = secrets.token_urlsafe(48), secrets.token_urlsafe(24)
        manager = SecurityManager(data / 'shadownet.db', secret)
        manager.create_user('smoke-admin', password, 'admin')
        env = dict(os.environ, SHADOWNET_ENV='production', SHADOWNET_DATA_DIR=str(data),
                   SHADOWNET_TOKEN_SECRET=secret, SHADOWNET_TRUSTED_HOSTS='127.0.0.1,localhost',
                   SHADOWNET_CHECKPOINT=str(checkpoint), SHADOWNET_CHECKPOINT_SHA256=EXPECTED_CHECKPOINT,
                   WEB_CONCURRENCY='1')
        process = None
        with (data / 'server.log').open('w+') as log, httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=20) as client:
            def start():
                child = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', str(port), '--workers', '1', '--ws-max-size', '8192', '--ws-max-queue', '4'], cwd=ROOT, env=env, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if child.poll() is not None:
                            log.seek(0)
                            raise RuntimeError('Production process exited: ' + log.read()[-2000:])
                        try:
                            if client.get('/api/ready').status_code == 200:
                                return child
                        except httpx.TransportError:
                            pass
                        time.sleep(0.25)
                    raise RuntimeError('Readiness timeout')
                except Exception:
                    stop(child)
                    raise

            def stop(child):
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)

            try:
                process = start()
                response = client.post('/api/auth/login', json={'username': 'smoke-admin', 'password': password})
                response.raise_for_status()
                headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
                report['checks']['production_startup'] = client.get('/api/ready').json()['status'] == 'ready'
                report['checks']['docs_disabled'] = all(client.get(path).status_code == 404 for path in ('/docs', '/redoc', '/openapi.json'))
                report['checks']['unauthenticated_mutation_denied'] = client.post('/api/simulate', json={'action':'block_ip'}).status_code == 401
                manifest = generate(data / 'pilot', duration_seconds=90)
                capture = data / 'pilot' / manifest['captures'][0]['path']
                response = client.post('/api/replays', headers=headers, files={'file': ('release.pcap', capture.read_bytes())})
                response.raise_for_status()
                replay = response.json()['replay_id']
                response = client.post(f'/api/replays/{replay}/advance', headers=headers, json={'seconds':60})
                response.raise_for_status()
                result = response.json()['inference']
                report['checks']['trained_inference'] = result['model_ready'] and len(result['forecast']) == 3
                report['checks']['claims_restricted'] = client.get('/api/ready').json()['claims_allowed'] is False
                report['checks']['shadow_only_forecasts'] = (result['operating_mode'] == 'research_shadow_mode' and not result['operational_alerting_enabled'] and all(not item['alert'] for item in result['forecast']))
                response = client.post('/api/telemetry/streams', headers=headers, json={'source': 'netflow', 'allowed_lateness': 0})
                response.raise_for_status()
                stream = response.json()['stream_id']
                endpoint = f'/api/telemetry/streams/{stream}'
                for timestamp in (10, 9):
                    response = client.post(endpoint + '/events', headers=headers,
                                           json={'records': [{'timestamp': timestamp}], 'flush': True})
                    response.raise_for_status()
                response = client.get(endpoint, headers=headers)
                response.raise_for_status()
                status = response.json()
                report['checks']['telemetry_status_and_late_event_boundary'] = (
                    status['events_accepted'] == status['host_graph']['event_count'] == 1
                    and status['events_rejected_late'] == 1 and status['kafka']['state'] == 'disconnected')
                response = client.delete(endpoint, headers=headers)
                response.raise_for_status()
                def ping(_):
                    started = time.perf_counter()
                    status = client.get('/api/health').status_code
                    return status, 1000 * (time.perf_counter() - started)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    samples = list(pool.map(ping, range(64)))
                report['checks']['concurrent_liveness'] = all(status == 200 for status, _ in samples)
                times = sorted(elapsed for _, elapsed in samples)
                report['health_smoke'] = {'requests':64, 'concurrency':8, 'p95_ms':round(times[60],2)}
                stop(process)
                process = None
                snapshot, restored = data / 'recovery-snapshot', data / 'recovered'
                backup(data, snapshot, secret)
                recovery = restore(snapshot, restored, secret)
                env['SHADOWNET_DATA_DIR'] = str(restored)
                process = start()
                report['checks']['restored_database_startup'] = recovery['audit_entries'] >= 3 and client.get('/api/ready').status_code == 200
                report['checks']['user_and_token_survive_restart'] = client.get('/api/auth/me', headers=headers).status_code == 200
                response = client.get('/api/admin/audit/verify', headers=headers)
                response.raise_for_status()
                report['checks']['audit_survives_restart'] = response.json()['valid'] and response.json()['entries'] >= 3
                report['checks']['logout_revokes_token'] = client.post('/api/auth/logout', headers=headers).status_code == 200 and client.get('/api/auth/me', headers=headers).status_code == 401
            finally:
                if process is not None:
                    stop(process)
    report['passed'] = all(report['checks'].values())
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8011)
    parser.add_argument('--report', type=Path, default=ROOT / 'data/workflow/production-smoke.json')
    args = parser.parse_args()
    result = verify(args.port)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
