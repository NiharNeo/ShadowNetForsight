from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.all import PcapReader

from pipeline.pcap_replay import summarize
from scripts.generate_controlled_lab_pcaps import generate as generate_pilot


REQUIRED_CAPTURE_COUNTS = {"train": 18, "validation": 6, "test": 6}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture_window_count(path: Path, window_seconds: int) -> int:
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    with PcapReader(str(path)) as reader:
        for packet in reader:
            summary = summarize(packet)
            if summary is None:
                continue
            first_timestamp = summary.timestamp if first_timestamp is None else first_timestamp
            last_timestamp = summary.timestamp
    if first_timestamp is None or last_timestamp is None:
        return 0
    return int((last_timestamp - first_timestamp) // window_seconds) + 1


def verify_pilot(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "pilot_only_not_for_final_claims":
        raise ValueError("Pilot manifest must explicitly prohibit final deployment claims")
    verified = []
    for capture in manifest.get("captures", []):
        path = manifest_path.parent / capture["path"]
        if not path.is_file():
            raise FileNotFoundError(path)
        actual_hash = sha256(path)
        if actual_hash != capture["sha256"]:
            raise ValueError(f"SHA-256 mismatch for {path.name}")
        windows = capture_window_count(path, int(manifest.get("window_seconds", 5)))
        if windows < 15:
            raise ValueError(f"{path.name} is too short for a 12-window history and 3-step horizon")
        verified.append({"path": str(path), "sha256": actual_hash, "windows": windows})
    if len(verified) != 2:
        raise ValueError("Pilot workflow requires exactly one benign and one attack-progression capture")
    return {"status": "passed", "captures": verified}


def validate_full_plan(plan_path: Path) -> dict[str, Any]:
    if not plan_path.is_file():
        raise FileNotFoundError(
            f"{plan_path} is missing. Copy datasets/pcap_training_plan.example.json and add independently collected captures."
        )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    partitions = plan.get("partitions", {})
    seen_paths: set[Path] = set()
    seen_hashes: set[str] = set()
    counts: dict[str, int] = {}
    for partition, required in REQUIRED_CAPTURE_COUNTS.items():
        entries = partitions.get(partition, [])
        counts[partition] = len(entries)
        if len(entries) < required:
            raise ValueError(f"{partition} requires at least {required} independent captures; found {len(entries)}")
        for entry in entries:
            path = Path(entry["path"])
            if not path.is_absolute():
                path = (plan_path.parent / path).resolve()
            path = path.resolve()
            if path in seen_paths:
                raise ValueError(f"Capture appears in more than one partition: {path}")
            seen_paths.add(path)
            if not path.is_file():
                raise FileNotFoundError(path)
            fingerprint = sha256(path)
            if fingerprint != str(entry.get("sha256", "")).lower():
                raise ValueError(f"SHA-256 mismatch for {path}")
            if fingerprint in seen_hashes:
                raise ValueError(f"Duplicate capture content cannot count as an independent session: {path}")
            seen_hashes.add(fingerprint)
            if not entry.get("timeline"):
                raise ValueError(f"Capture has no reviewed label timeline: {path}")
    return {"status": "passed", "partition_counts": counts, "unique_captures": len(seen_paths)}


def run_step(name: str, command: list[str], report: list[dict[str, Any]]) -> None:
    started = time.monotonic()
    environment = os.environ.copy()
    environment.setdefault("OMP_NUM_THREADS", "1")
    environment.setdefault("KMP_USE_SHM", "0")
    completed = subprocess.run(command, cwd=ROOT, check=False, env=environment)
    result = {"name": name, "command": command, "exit_code": completed.returncode,
              "duration_seconds": round(time.monotonic() - started, 2)}
    report.append(result)
    if completed.returncode:
        raise RuntimeError(f"Workflow step failed: {name}")


def write_report(path: Path, mode: str, status: str, checks: dict[str, Any], steps: list[dict[str, Any]], error: str | None = None) -> None:
    payload = {
        "schema_version": 1,
        "workflow": "ShadowNet validation and training",
        "mode": mode,
        "status": status,
        "checks": checks,
        "steps": steps,
        "error": error,
        "integrity": {
            "capture_provenance": "SHA-256",
            "application_audit": "HMAC-SHA256 hash chain",
            "blockchain": "not used; no multi-party trust requirement",
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ShadowNet's gated validation or full lab workflow")
    parser.add_argument("mode", choices=("pilot", "full"))
    parser.add_argument("--plan", type=Path, default=ROOT / "datasets" / "pcap_training_plan.json")
    parser.add_argument("--report", type=Path, default=ROOT / "data" / "workflow" / "latest.json")
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    steps: list[dict[str, Any]] = []
    checks: dict[str, Any] = {}
    try:
        pilot_dir = ROOT / "data" / "controlled-lab" / "pilot"
        generate_pilot(pilot_dir)
        checks["pilot"] = verify_pilot(pilot_dir / "pilot-manifest.json")
        if not args.skip_tests:
            run_step("unit_and_integration_tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], steps)
        if args.mode == "full":
            checks["full_data_gate"] = validate_full_plan(args.plan.resolve())
            run_step("build_pcap_dataset", [sys.executable, "-m", "pipeline.build_pcap_dataset", "--plan", str(args.plan.resolve()), "--output", "data/processed-pcap-corpus"], steps)
            run_step("train_static_baseline", [sys.executable, "-m", "pipeline.train_baseline", "--data", "data/processed-pcap-corpus", "--output", "models/pcap-onset-baseline"], steps)
            run_step("train_temporal_model", [sys.executable, "-m", "pipeline.train_lstm", "--data", "data/processed-pcap-corpus", "--output", "models/pcap-onset-gru", "--architecture", "gru", "--epochs", "80", "--patience", "12", "--hidden-size", "64", "--layers", "2", "--onset-loss-weight", "4"], steps)
            run_step("evaluate_held_out_test", [sys.executable, "-m", "pipeline.evaluate", "--data", "data/processed-pcap-corpus", "--checkpoint", "models/pcap-onset-gru/lstm.pt", "--baseline", "models/pcap-onset-baseline/baseline.joblib", "--output", "models/pcap-onset-gru/evaluation.json"], steps)
        write_report(args.report, args.mode, "passed", checks, steps)
        print(json.dumps({"status": "passed", "mode": args.mode, "report": str(args.report)}, indent=2))
        return 0
    except Exception as error:
        write_report(args.report, args.mode, "failed", checks, steps, str(error))
        print(json.dumps({"status": "failed", "mode": args.mode, "error": str(error), "report": str(args.report)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
