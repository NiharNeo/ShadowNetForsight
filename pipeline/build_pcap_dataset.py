from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from scapy.all import PcapReader

from pipeline.build_dataset import BuildConfig, FEATURES
from pipeline.pcap_calibration import pcap_states
from pipeline.pcap_replay import summarize
from pipeline.stage_mapping import STAGE_ORDER
from pipeline.feature_contract import PCAP_CONTRACT


REQUIRED_PARTITIONS = ("train", "validation", "test")
PCAP_UNOBSERVED_FEATURES = {"failed_auth_count", "identity_reuse_count"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _capture_start(path: Path) -> float:
    with PcapReader(str(path)) as reader:
        for packet in reader:
            summary = summarize(packet)
            if summary is not None:
                return summary.timestamp
    raise ValueError(f"{path.name} contains no IPv4 or IPv6 packets")


def _validate_timeline(entry: dict[str, Any], duration_seconds: float) -> list[dict[str, Any]]:
    if not math.isfinite(duration_seconds) or duration_seconds <= 0:
        raise ValueError("Capture duration must be positive and finite")
    timeline = entry.get("timeline")
    if not isinstance(timeline, list) or not timeline:
        raise ValueError(f"{entry.get('path', 'capture')} requires a non-empty timeline")
    validated = []
    previous_end = 0.0
    for index, interval in enumerate(timeline):
        start = float(interval.get("start_seconds", 0.0))
        end = float(interval.get("end_seconds", duration_seconds))
        raw_label = interval.get("label", -1)
        if isinstance(raw_label, bool) or not isinstance(raw_label, (int, float)) or raw_label not in (0, 1):
            raise ValueError(f"timeline interval {index} label must be exactly 0 or 1")
        label = int(raw_label)
        stage = str(interval.get("stage", ""))
        if label not in (0, 1):
            raise ValueError(f"timeline interval {index} label must be 0 or 1")
        if stage not in STAGE_ORDER:
            raise ValueError(f"timeline interval {index} has unknown stage: {stage}")
        if (label == 0) != (stage == "Normal"):
            raise ValueError(f"timeline interval {index} must pair label 0 with Normal and label 1 with an attack stage")
        if not math.isfinite(start) or not math.isfinite(end):
            raise ValueError(f"timeline interval {index} timestamps must be finite")
        if start < previous_end or end <= start or end > duration_seconds + 1e-6:
            raise ValueError(f"timeline interval {index} is overlapping or outside capture duration")
        validated.append({"start_seconds": start, "end_seconds": end, "label": label, "stage": stage})
        previous_end = end
    return validated


def _targets(window_count: int, window_seconds: int, timeline: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    attack = np.zeros(window_count, dtype=np.float32)
    stage = np.zeros(window_count, dtype=np.int64)
    covered = np.zeros(window_count, dtype=bool)
    for index in range(window_count):
        midpoint = (index + 0.5) * window_seconds
        for interval in timeline:
            if interval["start_seconds"] <= midpoint < interval["end_seconds"]:
                attack[index] = float(interval["label"])
                stage[index] = STAGE_ORDER[interval["stage"]]
                covered[index] = True
                break
    if not covered.all():
        missing = np.flatnonzero(~covered)
        raise ValueError(f"timeline does not label {len(missing)} window(s); first missing index is {int(missing[0])}")
    return attack, stage


def _capture_sequences(path: Path, entry: dict[str, Any], config: BuildConfig) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    actual_hash = _sha256(path)
    expected_hash = str(entry.get("sha256", "")).lower()
    if not expected_hash:
        raise ValueError(f"{path} requires a sha256 value for provenance")
    if actual_hash != expected_hash:
        raise ValueError(f"SHA-256 mismatch for {path}: expected {expected_hash}, found {actual_hash}")
    states = pcap_states(path, config.window_seconds)
    duration = len(states) * config.window_seconds
    timeline = _validate_timeline(entry, duration)
    attack, stage = _targets(len(states), config.window_seconds, timeline)
    matrix = np.asarray([[state[name] for name in FEATURES] for state in states], dtype=np.float32)
    count = len(states) - config.sequence_length - config.horizon + 1
    if count <= 0:
        required = (config.sequence_length + config.horizon) * config.window_seconds
        raise ValueError(f"{path.name} needs at least {required} seconds of labelled traffic")
    x = np.stack([matrix[i:i + config.sequence_length] for i in range(count)])
    y_state = np.stack([matrix[i + config.sequence_length:i + config.sequence_length + config.horizon] for i in range(count)])
    y_attack = np.stack([attack[i + config.sequence_length:i + config.sequence_length + config.horizon] for i in range(count)])
    y_stage = np.stack([stage[i + config.sequence_length:i + config.sequence_length + config.horizon] for i in range(count)])
    anchor_attack = np.asarray([attack[i + config.sequence_length - 1] for i in range(count)], dtype=np.float32)
    anchor_stage = np.asarray([stage[i + config.sequence_length - 1] for i in range(count)], dtype=np.int64)
    capture_start = _capture_start(path)
    anchor_values = [
        datetime.fromtimestamp(capture_start + (i + config.sequence_length - 1) * config.window_seconds,
                               tz=timezone.utc).isoformat()
        for i in range(count)
    ]
    anchor = np.asarray(anchor_values, dtype="U40")
    capture_id = np.asarray([path.name] * count, dtype=f"U{max(len(path.name), 1)}")
    arrays = {"x": x, "y_state": y_state, "y_attack": y_attack, "y_stage": y_stage,
              "anchor_attack": anchor_attack, "anchor_stage": anchor_stage,
              "anchor_time": anchor, "capture_id": capture_id}
    metadata = {"path": str(path), "sha256": actual_hash, "bytes": path.stat().st_size,
                "windows": len(states), "duration_seconds": duration, "sequences": count,
                "timeline": timeline}
    return arrays, metadata


def build(plan_path: Path, output_dir: Path) -> dict[str, Any]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    config = BuildConfig(window_seconds=int(plan.get("window_seconds", 5)),
                         sequence_length=int(plan.get("sequence_length", 12)),
                         horizon=int(plan.get("horizon", 3)))
    partitions = plan.get("partitions", {})
    missing = [name for name in REQUIRED_PARTITIONS if not partitions.get(name)]
    if missing:
        raise ValueError(f"PCAP plan requires non-empty partitions: {missing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "dataset": plan.get("dataset", plan_path.stem),
        "source_plan": str(plan_path),
        "feature_contract": PCAP_CONTRACT,
        "config": {"window_seconds": config.window_seconds, "sequence_length": config.sequence_length, "horizon": config.horizon},
        "features": FEATURES,
        "feature_observed": {name: name not in PCAP_UNOBSERVED_FEATURES for name in FEATURES},
        "stage_order": STAGE_ORDER,
        "partitions": {},
        "warnings": [
            "Timeline labels are supplied by the dataset curator and must be independently reviewed.",
            "Sequences never cross capture or partition boundaries.",
            "Raw PCAP does not provide authentication identities; add Cowrie or identity telemetry for those features.",
        ],
    }
    plan_dir = plan_path.parent
    for partition in REQUIRED_PARTITIONS:
        batches: list[dict[str, np.ndarray]] = []
        captures = []
        for entry in partitions[partition]:
            path = Path(entry["path"])
            if not path.is_absolute():
                path = (plan_dir / path).resolve()
            if not path.is_file():
                raise FileNotFoundError(path)
            arrays, metadata = _capture_sequences(path, entry, config)
            batches.append(arrays)
            captures.append(metadata)
        keys = batches[0].keys()
        combined = {key: np.concatenate([batch[key] for batch in batches], axis=0) for key in keys}
        np.savez_compressed(output_dir / f"{partition}.npz", **combined)
        manifest["partitions"][partition] = {
            "sequences": int(len(combined["x"])),
            "positive_targets": int(combined["y_attack"].sum()),
            "captures": captures,
        }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build leakage-safe labelled raw-PCAP network-state partitions")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(json.dumps(build(args.plan, args.output), indent=2))
