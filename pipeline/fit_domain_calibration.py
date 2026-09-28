from __future__ import annotations

import argparse
import json
import hashlib
import os
from pathlib import Path

import numpy as np
import torch

from pipeline.calibration import fit_temperature
from pipeline.temporal_model import build_temporal_model
from pipeline.train_lstm import load_split, normalize, predictions, tune_threshold


def fit_domain_calibration(checkpoint_path: Path, data_dir: Path, domain: str, output: Path) -> dict:
    """Fit a target-network calibration profile using its validation partition only."""
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model = build_temporal_model(checkpoint["model_config"])
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    raw_validation = load_split(data_dir, "validation")
    validation = normalize(
        raw_validation,
        np.asarray(checkpoint["normalization_mean"], dtype=np.float32),
        np.asarray(checkpoint["normalization_scale"], dtype=np.float32),
        checkpoint.get("input_transform", "identity"),
        checkpoint.get("normalization_clip"),
    )
    with torch.no_grad():
        logits = model(torch.tensor(validation["x"], dtype=torch.float32))["attack_logits"].numpy()
    temperature = fit_temperature(logits, (validation["y_attack"] > 0).astype(np.float32))
    calibrated = predictions(model, validation, temperature)
    thresholds, validation_f1 = tune_threshold(validation, calibrated)
    profile = {
        "schema_version": 2,
        "domain": domain,
        "fit_partition": "validation",
        "sample_count": int(len(validation["x"])),
        "temperature": temperature.tolist(),
        "decision_threshold": thresholds,
        "validation_macro_f1": validation_f1,
        "checkpoint": checkpoint_path.name,
        "checkpoint_sha256": hashlib.sha256(checkpoint_path.read_bytes()).hexdigest(),
        "ood_lower": np.asarray(checkpoint["ood_lower"]).tolist(),
        "ood_upper": np.asarray(checkpoint["ood_upper"]).tolist(),
        "ood_threshold": float(checkpoint["ood_threshold"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    os.replace(temporary, output)
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(description="Fit validation-only network-specific calibration")
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(fit_domain_calibration(args.checkpoint, args.data, args.domain, args.output), indent=2))


if __name__ == "__main__":
    main()
