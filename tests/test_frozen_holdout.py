from pathlib import Path
import hashlib
import tempfile
import unittest
from scripts.evaluate_iot23_holdout import verify_frozen
from scripts.train_iot23_pilot import counts

class FrozenHoldoutTests(unittest.TestCase):
    def test_changed_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'checkpoint'; path.write_bytes(b'original')
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(verify_frozen(path,digest),digest)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'Frozen artifact changed'):
                verify_frozen(path,digest)

    def test_empty_and_negative_only_support_do_not_invent_recall(self):
        self.assertIsNone(counts([],[])['recall'])
        self.assertIsNone(counts([0,0],[0,1])['recall'])
        self.assertEqual(counts([0,0],[0,1])['false_positive_rate'],.5)
