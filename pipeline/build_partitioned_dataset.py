from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from pipeline.feature_contract import CSV_CONTRACT

import numpy as np
import pandas as pd

from pipeline.build_dataset import BuildConfig, FEATURES, aggregate_windows, load_flows, make_sequences
from pipeline.stage_mapping import LABEL_RULES, STAGE_ORDER


def build_partitioned(plan_path: Path, raw_dir: Path, output_dir: Path, config: BuildConfig) -> dict:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    output_dir.mkdir(parents=True, exist_ok=True)
    state_dir = output_dir / "network_states"
    state_dir.mkdir(exist_ok=True)
    split_sizes: dict[str, int] = {}
    file_reports = []

    for partition in ("train", "validation", "test"):
        partition_sequences: list[dict[str, np.ndarray]] = []
        for entry in plan["partitions"][partition]:
            path = raw_dir / entry["key"]
            if not path.exists():
                raise FileNotFoundError(f"Missing planned {partition} day: {path}")
            actual_bytes = path.stat().st_size
            if actual_bytes != entry["bytes"]:
                raise ValueError(f"Size mismatch for {path.name}: expected {entry['bytes']}, found {actual_bytes}")
            flows = load_flows([path])
            windows = aggregate_windows(flows, config.window_seconds)
            sequences = make_sequences(windows, config)
            partition_sequences.append(sequences)
            windows.to_csv(state_dir / f"{path.stem}.states.csv", index=False)
            file_reports.append({
                "partition": partition,
                "file": path.name,
                "bytes": actual_bytes,
                "flows": len(flows),
                "states": len(windows),
                "sequences": len(sequences["x"]),
                "stage_counts": {str(key): int(value) for key, value in windows["stage"].value_counts().items()},
            })
            del flows, windows
        merged = {key: np.concatenate([item[key] for item in partition_sequences], axis=0) for key in partition_sequences[0]}
        np.savez_compressed(output_dir / f"{partition}.npz", **merged)
        split_sizes[partition] = len(merged["x"])

    manifest = {
        "feature_contract": CSV_CONTRACT,
        "dataset": plan["dataset"],
        "split_strategy": plan["strategy"],
        "config": asdict(config),
        "features": FEATURES,
        "stage_order": STAGE_ORDER,
        "label_rules": [{"pattern": pattern, "stage": stage, "rationale": rationale} for pattern, stage, rationale in LABEL_RULES],
        "split_sizes": split_sizes,
        "files": file_reports,
        "plan": str(plan_path),
        "warning": "Attack stages are documented proxies. Whole-day partitions prevent sequence leakage across days.",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build fixed whole-day CSE-CIC-IDS2018 partitions.")
    parser.add_argument("--plan", type=Path, default=Path("datasets/cic2018_split.json"))
    parser.add_argument("--raw", type=Path, default=Path("data/raw/cic2018"))
    parser.add_argument("--output", type=Path, default=Path("data/processed-cic2018"))
    parser.add_argument("--window-seconds", type=int, default=5)
    parser.add_argument("--sequence-length", type=int, default=12)
    parser.add_argument("--horizon", type=int, default=3)
    args = parser.parse_args()
    configuration = BuildConfig(window_seconds=args.window_seconds, sequence_length=args.sequence_length, horizon=args.horizon)
    print(json.dumps(build_partitioned(args.plan, args.raw, args.output, configuration), indent=2))
