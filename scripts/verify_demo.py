"""Verify the running localhost Docker demo without printing credentials."""
import json
import hashlib
from pathlib import Path
import sys
import time
import httpx
from websockets.sync.client import connect

ROOT = Path(__file__).resolve().parents[1]


def verify():
    checks = {}
    with httpx.Client(base_url='http://localhost:8000', timeout=30) as client:
        response = client.get('/api/ready')
        response.raise_for_status()
        checks['ready'] = response.json()['status'] == 'ready'
        checks['team_branding'] = 'TECHTREK' in client.get('/').text
        checks['unauthenticated_upload_denied'] = client.post('/api/replays').status_code == 401
        response = client.post('/api/auth/login', json=json.loads((ROOT / 'data/demo/access.json').read_text()))
        response.raise_for_status()
        token = response.json()['access_token']
        headers = {'Authorization': 'Bearer ' + token}
        for filename in ['pilot-benign-3m.pcap', 'pilot-attack-3m.pcap']:
            response = client.post('/api/replays', headers=headers, files={'file': (filename, (ROOT / 'data/demo/captures' / filename).read_bytes())})
            response.raise_for_status()
            metadata = response.json()
            assert metadata['capture_sha256'] == hashlib.sha256((ROOT / 'data/demo/captures' / filename).read_bytes()).hexdigest()
            assert metadata['checkpoint_sha256'] == hashlib.sha256((ROOT / 'models/cic2018-phase1-lstm/lstm.pt').read_bytes()).hexdigest()
            replay = metadata['replay_id']
            try:
                with connect(f'ws://localhost:8000/ws/replays/{replay}', open_timeout=20) as socket:
                    socket.send(json.dumps({'type': 'auth', 'token': token}))
                    assert json.loads(socket.recv(timeout=20))['type'] == 'connected'
                    for _ in range(4):
                        socket.send(json.dumps({'seconds': 60}))
                        result = json.loads(socket.recv(timeout=30))
                        assert result['type'] == 'replay_update', result.get('detail')
                        forecast = result['inference']
                        assert forecast['model_ready'] and len(forecast['forecast']) == 3
                        assert not forecast['operational_alerting_enabled']
                        assert not forecast['feature_compatibility']['compatible']
                        assert 'feature_contract_unverified' in forecast['uncertainty']['suppression_reasons']
                        assert all(not point['shadow_alert'] for point in forecast['forecast'])
                        assert all(not point['alert'] for point in forecast['forecast'])
                        json.dumps(result, allow_nan=False)
                        if result['complete']:
                            break
                    checks[filename] = bool(result['complete'])
            finally:
                client.delete(f'/api/replays/{replay}', headers=headers).raise_for_status()
        response = client.post('/api/simulate', headers=headers, json={'action': 'close_port'})
        checks['illustrative_simulation'] = response.status_code == 200
        checks['logout'] = client.post('/api/auth/logout', headers=headers).status_code == 200
        checks['token_revoked'] = client.get('/api/auth/me', headers=headers).status_code == 401
    report = {'scope': 'running localhost demo: authenticated HTTP and WebSocket replay of synthetic captures', 'checks': checks, 'passed': all(checks.values())}
    path = ROOT / 'docs/release-evidence/docker-demo.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(verify())
