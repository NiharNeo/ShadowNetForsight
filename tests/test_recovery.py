import json
from pathlib import Path
import tempfile
import unittest

from backend.security import SecurityManager
from scripts.manage_backup import backup, restore


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'data'
        self.secret = 'recovery-test-secret'
        self.manager = SecurityManager(self.source / 'shadownet.db', self.secret)
        self.manager.create_user('operator', 'test-password', 'operator')
        self.manager.audit('operator', 'RECOVERY_TEST', '/', 200)
        (self.source / 'calibrations').mkdir()
        (self.source / 'calibrations/local.json').write_text('{"domain":"local"}')
        (self.source / 'shadownet.secret').write_text('never export secrets')
        (self.source / 'uploads').mkdir()
        (self.source / 'uploads/private.pcap').write_bytes(b'private capture')
        self.snapshot, self.restored = self.root / 'snapshot', self.root / 'restored'

    def test_restores_accounts_audit_and_profiles_without_exporting_secrets_or_captures(self):
        backup(self.source, self.snapshot, self.secret)
        token = self.manager.authenticate('operator', 'test-password')
        result = restore(self.snapshot, self.restored, self.secret)
        recovered = SecurityManager(self.restored / 'shadownet.db', self.secret)
        self.assertEqual(result['audit_entries'], 1)
        self.assertIsNotNone(recovered.authenticate('operator', 'test-password'))
        self.assertIsNotNone(recovered.verify_token(token))
        self.assertTrue(recovered.verify_audit_chain()['valid'])
        self.assertEqual((self.restored / 'calibrations/local.json').read_text(), '{"domain":"local"}')
        self.assertFalse((self.snapshot / 'shadownet.secret').exists())
        self.assertFalse((self.snapshot / 'uploads').exists())
        self.assertEqual((self.restored / 'shadownet.db').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.restored.stat().st_mode & 0o777, 0o700)

    def test_wrong_secret_and_modified_snapshot_fail_without_publishing(self):
        backup(self.source, self.snapshot, self.secret)
        with self.assertRaises(ValueError):
            restore(self.snapshot, self.restored, 'wrong-secret')
        self.assertFalse(self.restored.exists())
        (self.snapshot / 'calibrations/local.json').write_text('{}')
        with self.assertRaises(ValueError):
            restore(self.snapshot, self.restored, self.secret)
        self.assertFalse(self.restored.exists())

    def test_existing_destination_is_never_overwritten(self):
        backup(self.source, self.snapshot, self.secret)
        with self.assertRaises(FileExistsError):
            backup(self.source, self.snapshot, self.secret)
        self.restored.mkdir()
        (self.restored / 'keep').write_text('existing data')
        with self.assertRaises(FileExistsError):
            restore(self.snapshot, self.restored, self.secret)
        self.assertEqual((self.restored / 'keep').read_text(), 'existing data')

    def test_tampered_audit_source_cannot_be_backed_up(self):
        with self.manager._connect() as db:
            db.execute("UPDATE audit_log SET username='tampered'")
        with self.assertRaises(ValueError):
            backup(self.source, self.snapshot, self.secret)
        self.assertFalse(self.snapshot.exists())

    def test_symlink_profile_is_rejected(self):
        (self.source / 'calibrations/escaped.json').symlink_to(self.source / 'shadownet.secret')
        with self.assertRaises(ValueError):
            backup(self.source, self.snapshot, self.secret)
        self.assertFalse(self.snapshot.exists())

    def test_modified_manifest_is_rejected(self):
        backup(self.source, self.snapshot, self.secret)
        path = self.snapshot / 'manifest.json'
        envelope = json.loads(path.read_text())
        envelope['manifest']['files']['../escape'] = '0' * 64
        path.write_text(json.dumps(envelope))
        with self.assertRaises(ValueError):
            restore(self.snapshot, self.restored, self.secret)
        self.assertFalse(self.restored.exists())
