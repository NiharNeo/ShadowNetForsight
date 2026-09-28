from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend import main
from backend.config import Settings
from backend.inference_service import LSTMInferenceService
from backend.replay_service import CapacityError, ReplayRegistry
from backend.security import Principal, SecurityManager
from backend.telemetry_service import TelemetryRegistry, KafkaBridge
from pipeline.telemetry import StreamingTelemetry, TelemetryEvent, adapt_netflow, adapt_cowrie
from scripts.generate_controlled_lab_pcaps import generate


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = SecurityManager(Path(self.temp.name) / 'db.sqlite', 'test-secret')
        self.manager.create_user('operator', 'a-valid-password', 'operator')

    def test_parallel_audits_form_one_chain(self):
        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(lambda i: self.manager.audit('operator', 'TEST', str(i), 200), range(60)))
        result = self.manager.verify_audit_chain()
        self.assertTrue(result['valid'])
        self.assertEqual(result['entries'], 60)

    def test_audit_health_cache_is_bounded_and_admin_verification_is_fresh(self):
        self.manager.audit('operator', 'TEST', '/', 200)
        with patch('backend.security.time.monotonic', return_value=100):
            self.assertTrue(self.manager.audit_health()['valid'])
        with self.manager._connect() as db:
            db.execute("UPDATE audit_log SET action='tampered'")
        with patch('backend.security.time.monotonic', return_value=104):
            self.assertTrue(self.manager.audit_health()['valid'])
            self.assertFalse(self.manager.verify_audit_chain()['valid'])
        with patch('backend.security.time.monotonic', return_value=105):
            result = self.manager.audit_health()
            self.assertFalse(result['valid'])
            self.assertEqual(result['first_invalid_id'], 1)
        result['valid'] = True
        with patch('backend.security.time.monotonic', return_value=106):
            self.assertFalse(self.manager.audit_health()['valid'])

    def test_password_replacement_and_logout_revoke_existing_tokens(self):
        token = self.manager.authenticate('operator', 'a-valid-password')
        self.manager.create_user('operator', 'another-password', 'operator', replace=True)
        self.assertIsNone(self.manager.verify_token(token))
        token = self.manager.authenticate('operator', 'another-password')
        self.manager.revoke_tokens('operator')
        self.assertIsNone(self.manager.verify_token(token))

    def test_reset_between_authentication_and_token_issue_still_revokes(self):
        issue = self.manager.issue_token
        def reset_then_issue(*args, **kwargs):
            self.manager.create_user('operator', 'replacement-password', 'operator', replace=True)
            return issue(*args, **kwargs)
        with patch.object(self.manager, 'issue_token', side_effect=reset_then_issue):
            token = self.manager.authenticate('operator', 'a-valid-password')
        self.assertIsNone(self.manager.verify_token(token))

    def test_database_connections_close_and_backup_restores_audit(self):
        self.manager.audit('operator', 'BACKUP_TEST', '/', 200)
        target = Path(self.temp.name) / 'restored.sqlite'
        with self.manager._connect() as source:
            with sqlite3.connect(target) as destination:
                source.backup(destination)
            destination.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            source.execute('SELECT 1')
        restored = SecurityManager(target, 'test-secret')
        self.assertTrue(restored.verify_audit_chain()['valid'])
        self.assertIsNotNone(restored.authenticate('operator', 'a-valid-password'))

    def test_expired_and_malformed_tokens_are_rejected(self):
        expired = self.manager.issue_token(Principal('operator', 'operator'), 0)
        for token in [expired, '', 'bad.token', 'x' * 5000, None]:
            self.assertIsNone(self.manager.verify_token(token))

    def test_login_limit_persists_and_expires(self):
        self.assertTrue(all(self.manager.allow_login('client', 'operator', 1000) for _ in range(10)))
        reopened = SecurityManager(self.manager.database, 'test-secret')
        self.assertFalse(reopened.allow_login('different-client', 'operator', 1001))
        self.assertTrue(reopened.allow_login('client', 'operator', 1301))

    def test_production_rejects_unsafe_settings(self):
        with patch.dict(os.environ, {'SHADOWNET_ENV': 'production', 'SHADOWNET_TOKEN_SECRET': ''}, clear=False):
            with self.assertRaises(ValueError):
                Settings.from_env()


class TelemetryRegressionTests(unittest.TestCase):
    def test_ipfix_milliseconds_and_netflow_uptime_have_correct_units(self):
        self.assertEqual(adapt_netflow({'flowEndMilliseconds': 1700000000123}).timestamp, 1700000000.123)
        self.assertEqual(adapt_netflow({'LAST_SWITCHED': 9000, 'sysUpTime': 11000, 'unix_secs': 1700000000}).timestamp, 1699999998)
        with self.assertRaises(ValueError):
            adapt_netflow({'LAST_SWITCHED': 100})

    def test_legacy_cowrie_naive_timestamp_is_utc(self):
        self.assertEqual(adapt_cowrie({'timestamp': '1970-01-01T00:00:01'}).timestamp, 1)

    def test_invalid_numeric_telemetry_is_rejected(self):
        for value in [float('inf'), float('nan'), -1]:
            with self.assertRaises(ValueError):
                TelemetryEvent(value, 'a', 'b')
        with self.assertRaises(ValueError):
            adapt_netflow({'timestamp': 1, 'src_port': 70000})

    def test_large_gap_rejection_is_atomic(self):
        stream = StreamingTelemetry()
        with self.assertRaises(ValueError):
            stream.ingest([TelemetryEvent(1, 'a', 'b'), TelemetryEvent(10**12, 'a', 'b')])
        self.assertEqual(stream.accepted, 0)
        self.assertIsNone(stream.origin)
        self.assertEqual(stream.windows, {})

    def test_window_capacity_cannot_be_bypassed_by_repeated_batches(self):
        stream = StreamingTelemetry()
        stream.max_window_records = 2
        stream.ingest([TelemetryEvent(1, 'a', 'b'), TelemetryEvent(2, 'a', 'b')])
        with self.assertRaises(ValueError):
            stream.ingest([TelemetryEvent(3, 'a', 'b')])
        self.assertEqual(stream.accepted, 2)

    def test_late_events_do_not_change_host_evidence(self):
        registry = TelemetryRegistry(main.inference_service)
        self.addCleanup(registry.close)
        key, handle = registry.create('netflow', 5, 0)
        handle.ingest_events([TelemetryEvent(10, 'a', 'b')], flush=True)
        result = handle.ingest_events(iter([TelemetryEvent(9, 'late-host', 'b'),
                                            TelemetryEvent(16, 'c', 'd')]))
        self.assertEqual(result['events_accepted'], 1)
        self.assertEqual(result['events_rejected_late'], 1)
        status = registry.status(key)
        self.assertEqual(status['events_accepted'], status['host_graph']['event_count'])
        self.assertEqual(status['host_graph']['event_count'], 2)
        self.assertNotIn('late-host', [host['host'] for host in status['host_graph']['top_hosts']])
        self.assertEqual(status['kafka']['state'], 'disconnected')

    def test_status_is_consistent_during_concurrent_ingestion(self):
        registry = TelemetryRegistry(main.inference_service)
        self.addCleanup(registry.close)
        key, handle = registry.create('netflow', 5, 0)
        def operation(index):
            if index % 2:
                handle.ingest_events([TelemetryEvent(1, str(index), 'b')])
            status = registry.status(key)
            self.assertEqual(status['events_accepted'], status['host_graph']['event_count'])
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(operation, range(200)))
        self.assertEqual(registry.status(key)['events_accepted'], 100)
        registry.remove(key)
        with self.assertRaises(KeyError):
            handle.status()

    def test_kafka_failure_is_visible_and_unprocessed_batch_is_not_committed(self):
        consumer = MagicMock()
        consumer.poll.side_effect = ValueError('private broker details')
        handle = MagicMock()
        with patch('kafka.KafkaConsumer', return_value=consumer):
            bridge = KafkaBridge(handle, 'localhost:9092', 'events', 'test')
        with self.assertLogs('backend.telemetry_service', level='ERROR'):
            bridge.start()
            bridge.thread.join(timeout=5)
        self.assertFalse(bridge.thread.is_alive())
        self.assertEqual(bridge.status(), {'state': 'failed', 'connected': False, 'error_type': 'ValueError'})
        consumer.commit.assert_not_called()
        bridge.close()
        consumer.close.assert_called_once()

    def test_kafka_ingestion_failure_never_commits_offsets(self):
        consumer, handle = MagicMock(), MagicMock()
        consumer.poll.return_value = {'partition': [MagicMock(value='{}')]}
        handle.ingest_events.side_effect = ValueError('invalid telemetry')
        with patch('kafka.KafkaConsumer', return_value=consumer):
            bridge = KafkaBridge(handle, 'localhost:9092', 'events', 'test')
        with patch('backend.telemetry_service.adapt_message', return_value=TelemetryEvent(1, 'a', 'b')), \
             self.assertLogs('backend.telemetry_service', level='ERROR'):
            bridge.start()
            bridge.thread.join(timeout=5)
        self.assertFalse(bridge.thread.is_alive())
        consumer.commit.assert_not_called()
        self.assertEqual(bridge.status()['state'], 'failed')
        consumer.close.assert_called_once()

    def test_kafka_start_failure_releases_consumer_and_registry_entry(self):
        registry = TelemetryRegistry(main.inference_service)
        self.addCleanup(registry.close)
        key, _ = registry.create('netflow', 5, 0)
        consumer = MagicMock()
        with patch('kafka.KafkaConsumer', return_value=consumer), \
             patch('backend.telemetry_service.Thread.start', side_effect=RuntimeError('thread unavailable')):
            with self.assertRaises(RuntimeError):
                registry.connect_kafka(key, 'localhost:9092', 'events', 'test')
        consumer.close.assert_called_once()
        self.assertEqual(registry.status(key)['kafka']['state'], 'disconnected')

    def test_kafka_commits_only_after_successful_ingestion(self):
        consumer = MagicMock()
        handle = MagicMock()
        with patch('kafka.KafkaConsumer', return_value=consumer):
            bridge = KafkaBridge(handle, 'localhost:9092', 'events', 'test')
        message = MagicMock(value='{}')
        consumer.poll.return_value = {'partition': [message]}
        def commit():
            handle.ingest_events.assert_called_once()
            bridge.stop_event.set()
        consumer.commit.side_effect = commit
        with patch('backend.telemetry_service.adapt_message', return_value=TelemetryEvent(1, 'a', 'b')):
            bridge.start()
            bridge.thread.join(timeout=5)
        self.assertFalse(bridge.thread.is_alive())
        consumer.commit.assert_called_once()
        consumer.close.assert_called_once()
        self.assertEqual(bridge.status()['state'], 'stopped')



class ApiHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.security = SecurityManager(self.root / 'db.sqlite', 'integration-test-secret')
        for role in ('viewer', 'operator', 'admin'):
            self.security.create_user(role, 'a-valid-password', role)
        self.registry = ReplayRegistry(self.root / 'uploads', main.inference_service)
        self.telemetry = TelemetryRegistry(main.inference_service)
        self.patches = [patch.object(main, 'security', self.security), patch.object(main, 'replays', self.registry), patch.object(main, 'telemetry', self.telemetry)]
        for item in self.patches:
            item.start()
        self.client = TestClient(main.app)
        self.tokens = {role: self.security.issue_token(Principal(role, role)) for role in ('viewer', 'operator', 'admin')}

    def tearDown(self):
        self.registry.close()
        self.telemetry.close()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def headers(self, role='operator'):
        return {'Authorization': 'Bearer ' + self.tokens[role]}

    def upload(self):
        manifest = generate(self.root / 'pilot', duration_seconds=90)
        path = self.root / 'pilot' / manifest['captures'][0]['path']
        response = self.client.post('/api/replays', headers=self.headers(), files={'file': ('sample.pcap', path.read_bytes(), 'application/octet-stream')})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['replay_id']

    def test_early_auth_failure_has_correlated_headers_and_audit(self):
        response = self.client.post('/api/replays', content=b'invalid multipart')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['www-authenticate'], 'Bearer')
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        with main.security._connect() as db:
            row = db.execute('SELECT details FROM audit_log ORDER BY id DESC LIMIT 1').fetchone()
        self.assertEqual(json.loads(row['details'])['request_id'], response.headers['x-request-id'])

    def test_unexpected_failure_is_redacted_and_correlated(self):
        with patch.object(main.security, 'verify_token', side_effect=RuntimeError('private internal data')), \
             self.assertLogs('shadownet.api', level='ERROR'):
            response = self.client.get('/api/auth/me', headers=self.headers())
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['detail'], 'Internal server error')
        self.assertNotIn('private internal data', response.text)
        self.assertIn('x-request-id', response.headers)

    def test_audit_failure_reports_uncertain_mutation_outcome(self):
        headers = self.headers()
        with patch.object(main.security, 'audit', side_effect=sqlite3.OperationalError('disk full')), \
             self.assertLogs('shadownet.api', level='ERROR'):
            response = self.client.post('/api/auth/logout', headers=headers)
        self.assertEqual(response.status_code, 503)
        self.assertIn('may have completed', response.json()['detail'])
        self.assertIn('x-request-id', response.headers)
        self.assertEqual(self.client.get('/api/auth/me', headers=headers).status_code, 401)

    def test_health_readiness_security_headers_and_host_filter(self):
        response = self.client.get('/api/ready')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['claims_allowed'])
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        self.assertIn('frame-ancestors', response.headers['content-security-policy'])
        self.assertEqual(self.client.get('/api/health', headers={'Host': 'evil.example'}).status_code, 400)
        with patch.object(main.inference_service, 'available', False):
            self.assertEqual(self.client.get('/api/ready').status_code, 503)
            self.assertEqual(self.client.get('/api/health').status_code, 200)

    def test_missing_model_rejects_new_ingestion(self):
        with patch.object(main.inference_service, 'available', False):
            response = self.client.post('/api/telemetry/streams', headers=self.headers(), json={})
        self.assertEqual(response.status_code, 503)

    def test_http_role_validation_and_bounded_advance(self):
        self.assertEqual(self.client.post('/api/simulate', headers=self.headers('viewer'), json={'action': 'block_ip'}).status_code, 403)
        for seconds in [0, -1, 61, 'NaN', 'Infinity']:
            response = self.client.post('/api/replays/none/advance', headers=self.headers(), json={'seconds': seconds})
            self.assertEqual(response.status_code, 422)
        self.assertEqual(self.client.post('/api/telemetry/streams', headers=self.headers(), json={'window_seconds': 10}).status_code, 422)

    def test_malformed_upload_returns_422_and_removes_file(self):
        response = self.client.post('/api/replays', headers=self.headers(), files={'file': ('bad.pcap', b'not a capture')})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(list(self.registry.upload_dir.iterdir()), [])

    def test_request_body_limit_before_parsing(self):
        response = self.client.post('/api/auth/login', content=b'x', headers={'content-length': str(3 * 1024 * 1024)})
        self.assertEqual(response.status_code, 413)
        response = self.client.post('/api/auth/login', content=b'x' * (2 * 1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)

    def test_chunked_body_limits_and_nan_errors_do_not_leak_inputs(self):
        response = self.client.post('/api/auth/login', content=iter([b'x' * (1024 * 1024)] * 3))
        self.assertEqual(response.status_code, 413)
        response = self.client.post('/api/replays/x/advance', headers={**self.headers(), 'Content-Type': 'application/json'}, content='{"seconds": NaN}')
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('input', response.json()['detail'][0])
        response = self.client.post('/api/auth/login', json={'username':'x','password':'sensitive-test-value'})
        self.assertNotIn('sensitive-test-value', response.text)

    def test_calibration_metadata_requires_auth_and_admin_upload_is_prechecked(self):
        self.assertEqual(self.client.get('/api/calibration/profiles').status_code, 401)
        self.assertEqual(self.client.get('/api/calibration/profiles', headers=self.headers('viewer')).status_code, 200)
        response = self.client.post('/api/calibration/profiles', headers=self.headers(), content=b'malformed body')
        self.assertEqual(response.status_code, 403)

    def test_login_throttle_and_logout(self):
        for _ in range(10):
            self.assertEqual(self.client.post('/api/auth/login', json={'username': 'viewer', 'password': 'wrong'}).status_code, 401)
        self.assertEqual(self.client.post('/api/auth/login', json={'username': 'viewer', 'password': 'wrong'}).status_code, 429)
        self.assertEqual(self.client.post('/api/auth/logout', headers=self.headers('viewer')).status_code, 200)
        self.assertEqual(self.client.get('/api/auth/me', headers=self.headers('viewer')).status_code, 401)

    def test_kafka_requires_admin_and_broker_allowlist(self):
        body = {'bootstrap_servers': 'untrusted:9092', 'topic': 'events'}
        self.assertEqual(self.client.post('/api/telemetry/streams/x/kafka', headers=self.headers(), json=body).status_code, 403)
        self.assertEqual(self.client.post('/api/telemetry/streams/x/kafka', headers=self.headers('admin'), json=body).status_code, 403)

    def test_capture_evaluation_requires_operator_and_rejects_invalid_artifacts(self):
        body = {"report": {}, "labels": {}}
        self.assertEqual(self.client.post('/api/evaluate-capture', json=body).status_code, 401)
        self.assertEqual(self.client.post('/api/evaluate-capture', headers=self.headers('viewer'), json=body).status_code, 403)
        self.assertEqual(self.client.post('/api/evaluate-capture', headers=self.headers(), json=body).status_code, 422)

    def test_viewer_cannot_advance_websocket(self):
        replay_id = self.upload()
        with self.client.websocket_connect('/ws/replays/' + replay_id) as ws:
            ws.send_json({'type': 'auth', 'token': self.tokens['viewer']})
            with self.assertRaises(WebSocketDisconnect) as raised:
                ws.receive_json()
            self.assertEqual(raised.exception.code, 4403)
        self.assertEqual(self.registry.get(replay_id).status()['processed_packets'], 0)

    def test_websocket_rechecks_revocation(self):
        replay_id = self.upload()
        with self.client.websocket_connect('/ws/replays/' + replay_id) as ws:
            ws.send_json({'type': 'auth', 'token': self.tokens['operator']})
            self.assertEqual(ws.receive_json()['type'], 'connected')
            self.security.revoke_tokens('operator')
            ws.send_json({'seconds': 5})
            with self.assertRaises(WebSocketDisconnect) as raised:
                ws.receive_json()
            self.assertEqual(raised.exception.code, 4401)

    def test_websocket_heartbeat_keeps_position_and_rechecks_auth(self):
        replay_id = self.upload()
        with self.client.websocket_connect('/ws/replays/' + replay_id) as ws:
            ws.send_json({'type': 'auth', 'token': self.tokens['operator']})
            self.assertEqual(ws.receive_json()['type'], 'connected')
            before = self.registry.get(replay_id).status()
            ws.send_json({'type': 'ping'})
            self.assertEqual(ws.receive_json(), {'type': 'pong'})
            after = self.registry.get(replay_id).status()
            self.assertEqual(before, after)
            self.security.revoke_tokens('operator')
            ws.send_json({'type': 'ping'})
            with self.assertRaises(WebSocketDisconnect) as raised:
                ws.receive_json()
            self.assertEqual(raised.exception.code, 4401)

    def test_trained_replay_end_to_end_and_invalid_ws_message(self):
        replay_id = self.upload()
        with self.client.websocket_connect('/ws/replays/' + replay_id) as ws:
            ws.send_json({'type': 'auth', 'token': self.tokens['operator']})
            self.assertEqual(ws.receive_json()['type'], 'connected')
            ws.send_json({'seconds': 'NaN'})
            self.assertEqual(ws.receive_json()['type'], 'error')
            ws.send_json({'seconds': 60})
            result = ws.receive_json()
            self.assertTrue(result['inference']['model_ready'])
            self.assertEqual(len(result['inference']['forecast']), 3)
            self.assertEqual([p['offset_seconds'] for p in result['inference']['forecast']], [5, 10, 15])
        self.assertTrue(self.security.verify_audit_chain()['valid'])

    def test_session_capacity_and_expiration(self):
        self.registry.max_sessions = 1
        replay_id = self.upload()
        self.assertRaises(CapacityError, self.registry.create, self.registry.get(replay_id).path, 'capture.pcap', 5)
        self.registry.get(replay_id).last_used = time.monotonic() - 4000
        self.registry.cleanup()
        self.assertEqual(list(self.registry.upload_dir.iterdir()), [])
        with self.assertRaises(KeyError):
            self.registry.get(replay_id)

    def test_complete_replay_does_not_invent_empty_history(self):
        replay_id = self.upload()
        handle = self.registry.get(replay_id)
        handle.advance(60)
        handle.advance(60)
        end = handle.status()['simulated_time']
        result = handle.advance(60)
        self.assertEqual(result['states'], [])
        self.assertEqual(result['simulated_time'], end)

    def test_checkpoint_fingerprint_mismatch_fails_closed(self):
        with patch.dict(os.environ, {'SHADOWNET_CHECKPOINT_SHA256': '0' * 64}):
            service = LSTMInferenceService(main.inference_service.checkpoint_path)
        self.assertFalse(service.available)
        self.assertIn('SHA-256', service.error)


class ForecastPolicyTests(unittest.TestCase):
    def test_in_distribution_threshold_crossing_is_shadow_only(self):
        import numpy as np
        service = main.inference_service
        states = [dict.fromkeys(service.features, 0.0) for _ in range(service.sequence_length)]
        with patch.object(service, 'thresholds', [0.0] * service.model.horizon), \
             patch.object(service, 'ood_lower', np.full(len(service.features), -1e10)), \
             patch.object(service, 'ood_upper', np.full(len(service.features), 1e10)), \
             patch.object(service, 'ood_threshold', 1.0):
            result = service.predict(states)
        self.assertEqual(result['uncertainty']['status'], 'in_distribution')
        self.assertTrue(all(point['shadow_alert'] for point in result['forecast']))
        self.assertFalse(any(point['alert'] for point in result['forecast']))
        self.assertFalse(result['operational_alerting_enabled'])
        self.assertTrue(result['uncertainty']['alerts_suppressed'])

    def test_calibration_rejects_unsafe_shapes_values_and_provenance(self):
        import copy
        service = main.inference_service
        profile = dict(schema_version=2, domain='test-domain', fit_partition='validation',
                       checkpoint_sha256=service.checkpoint_sha256,
                       temperature=[1.0] * service.model.horizon,
                       decision_threshold=[0.5] * service.model.horizon,
                       ood_lower=[-1.0] * len(service.features),
                       ood_upper=[1.0] * len(service.features), ood_threshold=0.5)
        service.validate_calibration(profile)
        invalid = [('temperature', [0.0] * service.model.horizon),
                   ('temperature', [float('nan')] * service.model.horizon),
                   ('temperature', [1.0]), ('decision_threshold', [2.0] * service.model.horizon),
                   ('ood_lower', [2.0] * len(service.features)), ('ood_upper', []),
                   ('ood_threshold', float('inf')), ('checkpoint_sha256', None),
                   ('fit_partition', 'test'), ('domain', '../escape'), ('schema_version', 1)]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                candidate = copy.deepcopy(profile)
                candidate[key] = value
                with self.assertRaises(ValueError):
                    service.validate_calibration(candidate)


if __name__ == '__main__':
    unittest.main()
