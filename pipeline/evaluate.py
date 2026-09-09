from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from pipeline.temporal_model import ForecastHeads, build_temporal_model
from pipeline.transforms import normalize_features
from pipeline.calibration import calibrate_logits, ood_scores


def load_split(directory: Path, name: str = "test") -> dict[str, np.ndarray]:
    with np.load(directory / f"{name}.npz", allow_pickle=False) as archive:
        return {key: archive[key] for key in archive.files}


def safe_auc(metric, truth: np.ndarray, score: np.ndarray) -> float | None:
    return float(metric(truth, score)) if np.unique(truth).size > 1 else None


def false_positive_rate(truth: np.ndarray, prediction: np.ndarray) -> float:
    tn, fp, _, _ = confusion_matrix(truth, prediction, labels=[0, 1]).ravel()
    return float(fp / max(tn + fp, 1))


def load_lstm(checkpoint_path: Path) -> tuple[ForecastHeads, dict]:
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model = build_temporal_model(checkpoint["model_config"])
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    return model, checkpoint


def predict_lstm(model: ForecastHeads, checkpoint: dict, split: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    mean = np.asarray(checkpoint["normalization_mean"], dtype=np.float32)
    scale = np.asarray(checkpoint["normalization_scale"], dtype=np.float32)
    normalized = normalize_features(split["x"], mean, scale, checkpoint.get("input_transform", "identity"), checkpoint.get("normalization_clip"))
    with torch.no_grad():
        output = model(torch.tensor(normalized, dtype=torch.float32))
    return {
        "attack_probability": torch.sigmoid(calibrate_logits(output["attack_logits"], checkpoint.get("temperature"))).numpy(),
        "stage": output["stage_logits"].argmax(dim=-1).numpy(),
        "future_state": output["future_state"].numpy(),
    }


def threshold_vector(threshold: float | list[float], horizon: int) -> np.ndarray:
    values = np.asarray([threshold] * horizon if np.isscalar(threshold) else threshold, dtype=np.float32)
    if values.shape != (horizon,):
        raise ValueError(f"Expected {horizon} decision thresholds; found {values.size}.")
    return values


def horizon_metrics(split: dict[str, np.ndarray], prediction: dict[str, np.ndarray], threshold: float | list[float]) -> list[dict]:
    true_attack = (split["y_attack"] > 0).astype(np.int64)
    thresholds = threshold_vector(threshold, true_attack.shape[1])
    predicted_attack = (prediction["attack_probability"] >= thresholds.reshape(1, -1)).astype(np.int64)
    results = []
    for index in range(true_attack.shape[1]):
        truth = true_attack[:, index]
        binary = predicted_attack[:, index]
        probability = prediction["attack_probability"][:, index]
        results.append({
            "step": index + 1,
            "threshold": float(thresholds[index]),
            "precision": float(precision_score(truth, binary, zero_division=0)),
            "recall": float(recall_score(truth, binary, zero_division=0)),
            "f1": float(f1_score(truth, binary, zero_division=0)),
            "false_positive_rate": false_positive_rate(truth, binary),
            "roc_auc": safe_auc(roc_auc_score, truth, probability),
            "pr_auc": safe_auc(average_precision_score, truth, probability),
            "brier_score": float(brier_score_loss(truth, probability)),
            "stage_accuracy": float(accuracy_score(split["y_stage"][:, index], prediction["stage"][:, index])),
            "stage_macro_f1": float(f1_score(split["y_stage"][:, index], prediction["stage"][:, index], average="macro", zero_division=0)),
            "confusion_matrix": confusion_matrix(truth, binary, labels=[0, 1]).tolist(),
            "support": int(len(truth)),
            "positive_support": int(truth.sum()),
        })
    return results


def parse_anchor(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def early_warning(split: dict[str, np.ndarray], probability: np.ndarray, window_seconds: int, threshold: float | list[float]) -> dict:
    # Overlapping sequences forecast the same target window repeatedly. Collapse
    # them by capture and target timestamp before locating episode onsets.
    # The capture key prevents a partition boundary from becoming a false onset.
    actual_by_target: dict[tuple[str, datetime], int] = {}
    thresholds = threshold_vector(threshold, split["y_attack"].shape[1])
    forecasts_by_target: dict[tuple[str, datetime], list[tuple[datetime, float, float]]] = {}
    capture_ids = split.get("capture_id", np.asarray(["partition"] * len(split["anchor_time"])))
    for row, anchor_value in enumerate(split["anchor_time"]):
        issued_at = parse_anchor(anchor_value)
        capture_id = str(capture_ids[row])
        for horizon in range(split["y_attack"].shape[1]):
            target = issued_at + timedelta(seconds=(horizon + 1) * window_seconds)
            key = (capture_id, target)
            actual_by_target[key] = int(split["y_attack"][row, horizon] > 0)
            forecasts_by_target.setdefault(key, []).append((issued_at, float(probability[row, horizon]), float(thresholds[horizon])))

    onsets = []
    for capture_id in sorted(set(key[0] for key in actual_by_target)):
        ordered = sorted(key for key in actual_by_target if key[0] == capture_id)
        onsets.extend(key for index, key in enumerate(ordered)
                      if actual_by_target[key] == 1 and index > 0 and actual_by_target[ordered[index - 1]] == 0)
    leads = []
    for onset_key in onsets:
        onset = onset_key[1]
        valid = [(onset - issued).total_seconds() for issued, score, cutoff in forecasts_by_target.get(onset_key, []) if score >= cutoff and issued < onset]
        if valid:
            leads.append(max(valid))
    return {
        "threshold": thresholds.tolist(),
        "attack_onsets": len(onsets),
        "onsets_forecast_early": len(leads),
        "forecast_before_onset_rate": float(len(leads) / len(onsets)) if onsets else None,
        "mean_lead_seconds": float(np.mean(leads)) if leads else None,
        "median_lead_seconds": float(np.median(leads)) if leads else None,
        "max_lead_seconds": float(np.max(leads)) if leads else None,
        "note": "Null lead-time values mean this split contains no benign-to-attack onset or no early forecast; they are not zeros.",
    }


def degradation(horizons: list[dict]) -> dict:
    first = horizons[0]
    return {
        "f1_change_step1_to_last": float(horizons[-1]["f1"] - first["f1"]),
        "stage_accuracy_change_step1_to_last": float(horizons[-1]["stage_accuracy"] - first["stage_accuracy"]),
        "brier_change_step1_to_last": float(horizons[-1]["brier_score"] - first["brier_score"]),
    }


def baseline_metrics(model_path: Path, split: dict[str, np.ndarray]) -> dict | None:
    if not model_path.exists():
        return None
    bundle = joblib.load(model_path)
    x = split["x"][:, -1, :]
    truth = (split["y_attack"][:, 0] > 0).astype(np.int64)
    prediction = bundle["binary_model"].predict(x)
    return {
        "next_window_f1": float(f1_score(truth, prediction, zero_division=0)),
        "next_window_false_positive_rate": false_positive_rate(truth, prediction),
        "next_stage_accuracy": float(accuracy_score(split["y_stage"][:, 0], bundle["stage_model"].predict(x))),
    }


def evaluate(data_dir: Path, checkpoint_path: Path, baseline_path: Path, output_path: Path, threshold: float | list[float] | None, cross_data: Path | None = None) -> dict:
    manifest = json.loads((data_dir / "manifest.json").read_text(encoding="utf-8"))
    split = load_split(data_dir)
    model, checkpoint = load_lstm(checkpoint_path)
    resolved_threshold = threshold if threshold is not None else checkpoint.get("decision_threshold", 0.5)
    prediction = predict_lstm(model, checkpoint, split)
    normalized_test = normalize_features(split["x"], np.asarray(checkpoint["normalization_mean"]), np.asarray(checkpoint["normalization_scale"]), checkpoint.get("input_transform", "identity"), checkpoint.get("normalization_clip"))
    test_ood = ood_scores(normalized_test, np.asarray(checkpoint["ood_lower"]), np.asarray(checkpoint["ood_upper"])) if "ood_lower" in checkpoint else None
    horizons = horizon_metrics(split, prediction, resolved_threshold)
    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_split": "chronological_test",
        "threshold": threshold_vector(resolved_threshold, split["y_attack"].shape[1]).tolist(),
        "support": int(len(split["x"])),
        "horizons": horizons,
        "multi_horizon_degradation": degradation(horizons),
        "early_warning": early_warning(split, prediction["attack_probability"], manifest["config"]["window_seconds"], resolved_threshold),
        "future_state_mae_normalized": float(np.mean(np.abs(normalize_features(split["y_state"], np.asarray(checkpoint["normalization_mean"]), np.asarray(checkpoint["normalization_scale"]), checkpoint.get("input_transform", "identity"), checkpoint.get("normalization_clip")) - prediction["future_state"]))),
        "calibration": {"method": "per_horizon_temperature_scaling", "temperature": np.asarray(checkpoint.get("temperature", [1.0])).tolist()},
        "ood": {"threshold": checkpoint.get("ood_threshold"), "flag_rate": float((test_ood > checkpoint["ood_threshold"]).mean()) if test_ood is not None else None},
        "static_baseline": baseline_metrics(baseline_path, split),
        "cross_dataset": {"status": "not_run", "reason": "No cross-dataset processed directory supplied."},
        "claims_allowed": False,
        "limitations": [
            "The fixed CIC test day and CTU-13 are real datasets, but false-positive rates must improve before deployment claims.",
            "Cross-dataset labels and traffic distributions differ materially.",
            "Proxy stage labels are not native MITRE progression ground truth.",
        ],
    }
    if cross_data:
        cross_split = load_split(cross_data)
        cross_prediction = predict_lstm(model, checkpoint, cross_split)
        normalized_cross = normalize_features(cross_split["x"], np.asarray(checkpoint["normalization_mean"]), np.asarray(checkpoint["normalization_scale"]), checkpoint.get("input_transform", "identity"), checkpoint.get("normalization_clip"))
        cross_ood = ood_scores(normalized_cross, np.asarray(checkpoint["ood_lower"]), np.asarray(checkpoint["ood_upper"])) if "ood_lower" in checkpoint else None
        report["cross_dataset"] = {
            "status": "complete",
            "path": str(cross_data),
            "support": int(len(cross_split["x"])),
            "horizons": horizon_metrics(cross_split, cross_prediction, resolved_threshold),
            "ood_flag_rate": float((cross_ood > checkpoint["ood_threshold"]).mean()) if cross_ood is not None else None,
        }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate ShadowNet forecasts without temporal leakage.")
    parser.add_argument("--data", type=Path, default=Path("data/processed"))
    parser.add_argument("--checkpoint", type=Path, default=Path("data/models/lstm/lstm.pt"))
    parser.add_argument("--baseline", type=Path, default=Path("data/models/baseline/baseline.joblib"))
    parser.add_argument("--output", type=Path, default=Path("data/evaluation/report.json"))
    parser.add_argument("--threshold", type=float, help="Override all checkpoint-calibrated per-horizon thresholds.")
    parser.add_argument("--cross-data", type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(json.dumps(evaluate(args.data, args.checkpoint, args.baseline, args.output, args.threshold, args.cross_data), indent=2))
