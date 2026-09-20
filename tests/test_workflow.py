from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
