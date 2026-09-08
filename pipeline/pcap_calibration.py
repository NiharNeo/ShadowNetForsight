from __future__ import annotations

from pathlib import Path
import json

import numpy as np
import torch
from sklearn.metrics import brier_score_loss, f1_score, precision_score, recall_score
from scapy.all import PcapReader

from pipeline.calibration import fit_ood_profile, fit_temperature
from pipeline.pcap_replay import WindowAccumulator, summarize
from pipeline.temporal_model import build_temporal_model
from pipeline.train_lstm import tune_threshold
from pipeline.transforms import normalize_features


def pcap_states(path: Path, window_seconds: int = 5) -> list[dict[str, float]]:
    summaries = []
    with PcapReader(str(path)) as reader:
        for packet in reader:
            item = summarize(packet)
            if item is not None:
                summaries.append(item)
    if not summaries:
        raise ValueError(f"{path.name} contains no IPv4 or IPv6 packets")
    origin = summaries[0].timestamp
    windows: dict[int, WindowAccumulator] = {}
    for packet in summaries:
        index = max(int((packet.timestamp - origin) // window_seconds), 0)
        windows.setdefault(index, WindowAccumulator(origin + index * window_seconds)).add(packet)
    return [windows.get(index, WindowAccumulator(origin + index * window_seconds)).as_state()
            for index in range(max(windows) + 1)]


def _sequences(paths: list[Path], features: list[str], label: int, sequence_length: int, horizon: int) -> tuple[list[np.ndarray], list[np.ndarray]]:
    samples, labels = [], []
    for path in paths:
        states = pcap_states(path)
        matrix = np.asarray([[state[name] for name in features] for state in states], dtype=np.float32)
        count = len(matrix) - sequence_length - horizon + 1
        if count <= 0:
            raise ValueError(f"{path.name} needs at least {(sequence_length + horizon) * 5} seconds of usable capture history")
        samples.extend(matrix[index:index + sequence_length] for index in range(count))
        labels.extend(np.full(horizon, label, dtype=np.float32) for _ in range(count))
    return samples, labels


def fit_pcap_domain_calibration(checkpoint_path: Path, benign_paths: list[Path], attack_paths: list[Path], domain: str, output: Path) -> dict:
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model = build_temporal_model(checkpoint["model_config"])
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    features = list(checkpoint["features"])
    sequence_length = int(checkpoint.get("sequence_length", 12))
    horizon = int(checkpoint["model_config"]["horizon"])
    benign_x, benign_y = _sequences(benign_paths, features, 0, sequence_length, horizon)
    attack_x, attack_y = _sequences(attack_paths, features, 1, sequence_length, horizon)
    if len(benign_x) < 5 or len(attack_x) < 5:
        raise ValueError("Calibration needs at least five usable benign and five usable attack sequences")
    raw_x = np.stack(benign_x + attack_x)
    truth = np.stack(benign_y + attack_y)
    normalized = normalize_features(
        raw_x,
        np.asarray(checkpoint["normalization_mean"], dtype=np.float32),
        np.asarray(checkpoint["normalization_scale"], dtype=np.float32),
        checkpoint.get("input_transform", "identity"),
        checkpoint.get("normalization_clip"),
    )
    observed = np.asarray(checkpoint.get("feature_observed", np.ones(len(features), dtype=bool)), dtype=bool)
    normalized[:, :, ~observed] = 0.0
    with torch.no_grad():
        logits = model(torch.tensor(normalized, dtype=torch.float32))["attack_logits"].numpy()
    temperature = fit_temperature(logits, truth)
    probability = torch.sigmoid(torch.tensor(logits) / torch.tensor(temperature).reshape(1, -1)).numpy()
    split = {"y_attack": truth}
    thresholds, macro_f1 = tune_threshold(split, {"attack_probability": probability})
    ood = fit_ood_profile(normalized, normalized)
    binary = probability >= np.asarray(thresholds).reshape(1, -1)
    horizon_metrics = []
    for index in range(horizon):
        actual = truth[:, index].astype(int)
        predicted = binary[:, index].astype(int)
        negatives = actual == 0
        horizon_metrics.append({
            "step": index + 1,
            "f1": float(f1_score(actual, predicted, zero_division=0)),
            "precision": float(precision_score(actual, predicted, zero_division=0)),
            "recall": float(recall_score(actual, predicted, zero_division=0)),
            "false_positive_rate": float(predicted[negatives].mean()),
            "brier_score": float(brier_score_loss(actual, probability[:, index])),
        })
    profile = {
        "schema_version": 2,
        "domain": domain,
        "fit_partition": "validation",
        "source_type": "user_labelled_pcap",
        "sample_count": int(len(raw_x)),
        "benign_sequence_count": len(benign_x),
        "attack_sequence_count": len(attack_x),
        "temperature": temperature.tolist(),
        "decision_threshold": thresholds,
        "validation_macro_f1": macro_f1,
        "validation_horizons": horizon_metrics,
        "ood_lower": ood["lower"].tolist(),
        "ood_upper": ood["upper"].tolist(),
        "ood_threshold": ood["threshold"],
        "checkpoint": checkpoint_path.name,
        "warning": "Labels apply to each complete calibration capture. Evaluate on a separate untouched PCAP before operational use.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return profile
