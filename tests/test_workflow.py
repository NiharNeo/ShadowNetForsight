from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.build_pcap_dataset import _validate_timeline
from scripts.generate_controlled_lab_pcaps import generate
from scripts.run_project_workflow import validate_full_plan, verify_pilot


class WorkflowTests(unittest.TestCase):
    def test_pilot_gate_detects_capture_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generate(root, duration_seconds=90)
            self.assertEqual(verify_pilot(root / "pilot-manifest.json")["status"], "passed")
            with (root / "pilot-benign-15m.pcap").open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_pilot(root / "pilot-manifest.json")

    def test_full_gate_requires_partitions_and_rejects_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.pcap"
            capture.write_bytes(b"fixture")
            digest = hashlib.sha256(capture.read_bytes()).hexdigest()
            entry = {"path": str(capture), "sha256": digest,
                     "timeline": [{"start_seconds": 0, "end_seconds": 1, "label": 0, "stage": "Normal"}]}
            plan = root / "plan.json"
            plan.write_text(json.dumps({"partitions": {
                "train": [entry] * 18, "validation": [entry] * 6, "test": [entry] * 6,
            }}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "more than one partition"):
                validate_full_plan(plan)

    def test_full_gate_rejects_renamed_capture_copies(self) -> None:
        for duplicate_partition in ('train', 'validation', 'test'):
            with self.subTest(partition=duplicate_partition), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                partitions = {}
                for partition, count in (('train', 18), ('validation', 6), ('test', 6)):
                    entries = []
                    for index in range(count):
                        content = f'{partition}-{index}'.encode()
                        if partition == duplicate_partition and index == 1:
                            content = b'train-0'
                        path = root / f'{partition}-{index}.pcap'
                        path.write_bytes(content)
                        entries.append({'path': str(path), 'sha256': hashlib.sha256(content).hexdigest(),
                                        'timeline': [{'start_seconds': 0, 'end_seconds': 90, 'label': 0, 'stage': 'Normal'}]})
                    partitions[partition] = entries
                plan = root / 'plan.json'
                plan.write_text(json.dumps({'partitions': partitions}))
                with self.assertRaisesRegex(ValueError, 'Duplicate capture content'):
                    validate_full_plan(plan)

    def test_full_gate_accepts_unique_capture_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partitions = {}
            for partition, count in (('train', 18), ('validation', 6), ('test', 6)):
                entries = []
                for index in range(count):
                    content = f'{partition}-{index}'.encode()
                    path = root / f'{partition}-{index}.pcap'
                    path.write_bytes(content)
                    entries.append({'path': path.name, 'sha256': hashlib.sha256(content).hexdigest(),
                                    'timeline': [{'start_seconds': 0, 'end_seconds': 90, 'label': 0, 'stage': 'Normal'}]})
                partitions[partition] = entries
            plan = root / 'plan.json'
            plan.write_text(json.dumps({'partitions': partitions}))
            self.assertEqual(validate_full_plan(plan)['unique_captures'], 30)

    def test_timeline_rejects_nonfinite_timestamps_and_fractional_labels(self) -> None:
        valid = {'start_seconds': 0, 'end_seconds': 90, 'label': 1, 'stage': 'Reconnaissance'}
        for field, value in [('start_seconds', float('nan')), ('end_seconds', float('inf')),
                             ('end_seconds', float('nan')), ('label', 1.9), ('label', True)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                _validate_timeline({'timeline': [{**valid, field: value}]}, 90)
        for duration in (0, -1, float('nan'), float('inf')):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                _validate_timeline({'timeline': [valid]}, duration)



if __name__ == "__main__":
    unittest.main()
