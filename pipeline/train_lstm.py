from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from pipeline.temporal_model import ForecastHeads, build_temporal_model
from pipeline.transforms import normalize_features, transform_features
from pipeline.calibration import calibrate_logits, fit_ood_profile, fit_temperature, ood_scores
from pipeline.explainability import integrated_gradients


INPUT_TRANSFORM = "log1p_nonnegative"
NORMALIZATION_CLIP = 8.0
MAX_VALIDATION_FPR = 0.05


@dataclass(frozen=True)
class TrainingConfig:
    architecture: str = "lstm"
    epochs: int = 60
    batch_size: int = 32
    learning_rate: float = 1e-3
    hidden_size: int = 64
    layers: int = 2
    dropout: float = 0.2
    patience: int = 10
    state_loss_weight: float = 0.10
    onset_loss_weight: float = 0.0
    seed: int = 42


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


def load_split(directory: Path, name: str) -> dict[str, np.ndarray]:
    with np.load(directory / f"{name}.npz", allow_pickle=False) as archive:
        return {key: archive[key] for key in archive.files}


def normalize(split: dict[str, np.ndarray], mean: np.ndarray, scale: np.ndarray, transform: str = "identity", clip: float | None = None) -> dict[str, np.ndarray]:
    result = dict(split)
    result["x"] = normalize_features(split["x"], mean, scale, transform, clip)
    result["y_state"] = normalize_features(split["y_state"], mean, scale, transform, clip)
    return result


def tensors(split: dict[str, np.ndarray]) -> TensorDataset:
    return TensorDataset(
        torch.tensor(split["x"], dtype=torch.float32),
        torch.tensor(split["y_state"], dtype=torch.float32),
        torch.tensor(split["y_attack"], dtype=torch.float32),
        torch.tensor(split["y_stage"], dtype=torch.long),
    )


def onset_weights(split: dict[str, np.ndarray], boost: float) -> np.ndarray:
    weights = np.ones_like(split["y_attack"], dtype=np.float32)
    if boost <= 0 or "anchor_attack" not in split:
        return weights
    previous = np.concatenate([split["anchor_attack"].reshape(-1, 1), split["y_attack"][:, :-1]], axis=1)
    onset = (split["y_attack"] > 0) & (previous <= 0)
    return weights + onset.astype(np.float32) * boost


def loss_for(outputs: dict[str, torch.Tensor], target_state: torch.Tensor, target_attack: torch.Tensor, target_stage: torch.Tensor, state_weight: float, attack_weight: torch.Tensor | None = None, stage_weight: torch.Tensor | None = None, onset_weight: torch.Tensor | None = None) -> tuple[torch.Tensor, dict[str, float]]:
    attack_elements = nn.functional.binary_cross_entropy_with_logits(outputs["attack_logits"], target_attack, pos_weight=attack_weight, reduction="none")
    attack_loss = (attack_elements * onset_weight).mean() if onset_weight is not None else attack_elements.mean()
    stage_loss = nn.functional.cross_entropy(outputs["stage_logits"].flatten(0, 1), target_stage.flatten(), weight=stage_weight)
    state_loss = nn.functional.smooth_l1_loss(outputs["future_state"], target_state)
    total = attack_loss + stage_loss + state_weight * state_loss
    return total, {"attack": float(attack_loss.detach()), "stage": float(stage_loss.detach()), "state": float(state_loss.detach())}


def evaluate_loss(model: ForecastHeads, split: dict[str, np.ndarray], state_weight: float, attack_weight: torch.Tensor, stage_weight: torch.Tensor, onset_boost: float = 0.0) -> float:
    model.eval()
    with torch.no_grad():
        x, state, attack, stage = tensors(split).tensors
        onset_weight = torch.tensor(onset_weights(split, onset_boost), dtype=torch.float32)
        loss, _ = loss_for(model(x), state, attack, stage, state_weight, attack_weight, stage_weight, onset_weight)
    return float(loss)


def predictions(model: ForecastHeads, split: dict[str, np.ndarray], temperature: np.ndarray | list[float] | None = None) -> dict[str, np.ndarray]:
    model.eval()
    with torch.no_grad():
        output = model(torch.tensor(split["x"], dtype=torch.float32))
    return {
        "attack_probability": torch.sigmoid(calibrate_logits(output["attack_logits"], temperature)).numpy(),
        "stage": output["stage_logits"].argmax(dim=-1).numpy(),
        "future_state": output["future_state"].numpy(),
    }


def tune_threshold(split: dict[str, np.ndarray], prediction: dict[str, np.ndarray]) -> tuple[list[float], float]:
    truth = (split["y_attack"] > 0).astype(np.int64)
    # Neural scores can be poorly calibrated under day/family shift. Select
    # candidates from validation-score quantiles rather than assuming useful
    # probabilities lie on a fixed 0.05 grid.
    thresholds, scores = [], []
    for step in range(truth.shape[1]):
        probabilities = prediction["attack_probability"][:, step]
        candidates = np.unique(np.append(np.quantile(probabilities, np.linspace(0.0, 1.0, 401)), np.nextafter(probabilities.max(), np.inf)))
        negatives = truth[:, step] == 0
        scored = []
        for threshold in candidates:
            binary = probabilities >= threshold
            fpr = float(binary[negatives].mean()) if negatives.any() else 0.0
            if fpr <= MAX_VALIDATION_FPR:
                scored.append((float(f1_score(truth[:, step], binary, zero_division=0)), float(threshold)))
        score, threshold = max(scored, key=lambda item: (item[0], item[1]))
        thresholds.append(threshold)
        scores.append(score)
    return thresholds, float(np.mean(scores))


def metrics(split: dict[str, np.ndarray], prediction: dict[str, np.ndarray], threshold: float | list[float] = 0.5) -> dict:
    true_attack = (split["y_attack"] > 0).astype(np.int64)
    thresholds = np.asarray([threshold] * true_attack.shape[1] if np.isscalar(threshold) else threshold, dtype=np.float32)
    predicted_attack = (prediction["attack_probability"] >= thresholds.reshape(1, -1)).astype(np.int64)
    horizons = []
    for horizon in range(true_attack.shape[1]):
        negatives = true_attack[:, horizon] == 0
        false_positive_rate = float(predicted_attack[negatives, horizon].mean()) if negatives.any() else 0.0
        horizons.append({
            "step": horizon + 1,
            "precision": float(precision_score(true_attack[:, horizon], predicted_attack[:, horizon], zero_division=0)),
            "recall": float(recall_score(true_attack[:, horizon], predicted_attack[:, horizon], zero_division=0)),
            "f1": float(f1_score(true_attack[:, horizon], predicted_attack[:, horizon], zero_division=0)),
            "false_positive_rate": false_positive_rate,
            "stage_accuracy": float(accuracy_score(split["y_stage"][:, horizon], prediction["stage"][:, horizon])),
            "stage_macro_f1": float(f1_score(split["y_stage"][:, horizon], prediction["stage"][:, horizon], average="macro", zero_division=0)),
            "support": int(len(true_attack)),
        })
    return {
        "threshold": thresholds.tolist(),
        "horizons": horizons,
        "attack_f1_macro_over_horizons": float(np.mean([item["f1"] for item in horizons])),
        "stage_accuracy_macro_over_horizons": float(np.mean([item["stage_accuracy"] for item in horizons])),
        "future_state_mae_normalized": float(np.mean(np.abs(split["y_state"] - prediction["future_state"]))),
    }


def attribution_summary(model: ForecastHeads, split: dict[str, np.ndarray], features: list[str], temperature: np.ndarray) -> list[dict]:
    """Summarize Integrated Gradients on a deterministic bounded test sample."""
    sample_indices = np.linspace(0, len(split["x"]) - 1, min(32, len(split["x"])), dtype=int)
    importance = np.mean([
        integrated_gradients(model, split["x"][index : index + 1], temperature, horizon=0)["feature_importance"]
        for index in sample_indices
    ], axis=0)
    order = np.argsort(importance)[::-1]
    return [{"feature": features[index], "integrated_gradients_importance": float(importance[index])} for index in order]


def train(data_dir: Path, output_dir: Path, config: TrainingConfig) -> dict:
    if config.onset_loss_weight < 0:
        raise ValueError("onset_loss_weight must be non-negative")
    seed_everything(config.seed)
    manifest = json.loads((data_dir / "manifest.json").read_text(encoding="utf-8"))
    raw_train = load_split(data_dir, "train")
    raw_validation = load_split(data_dir, "validation")
    raw_test = load_split(data_dir, "test")
    missing = {"y_state", "y_attack", "y_stage", "x"} - raw_train.keys()
    if missing:
        raise ValueError(f"Processed data predates the world-model contract; rebuild it. Missing: {sorted(missing)}")

    transformed_train = transform_features(raw_train["x"], INPUT_TRANSFORM)
    mean = transformed_train.mean(axis=(0, 1), keepdims=True)
    scale = transformed_train.std(axis=(0, 1), keepdims=True)
    feature_observed = (scale.reshape(-1) >= 1e-6)
    scale[scale < 1e-6] = 1.0
    train_split = normalize(raw_train, mean, scale, INPUT_TRANSFORM, NORMALIZATION_CLIP)
    validation_split = normalize(raw_validation, mean, scale, INPUT_TRANSFORM, NORMALIZATION_CLIP)
    test_split = normalize(raw_test, mean, scale, INPUT_TRANSFORM, NORMALIZATION_CLIP)

    attack_positive = (train_split["y_attack"] > 0).sum(axis=0)
    attack_negative = train_split["y_attack"].shape[0] - attack_positive
    attack_weight = torch.tensor(np.clip(attack_negative / np.maximum(attack_positive, 1), 1.0, 20.0), dtype=torch.float32)
    stage_counts = np.bincount(train_split["y_stage"].reshape(-1), minlength=len(manifest["stage_order"]))
    stage_weights = np.zeros_like(stage_counts, dtype=np.float32)
    present = stage_counts > 0
    stage_weights[present] = stage_counts[present].sum() / (present.sum() * stage_counts[present])
    stage_weight = torch.tensor(stage_weights, dtype=torch.float32)

    model = build_temporal_model({"architecture": config.architecture, "feature_count": len(manifest["features"]), "stage_count": len(manifest["stage_order"]), "horizon": manifest["config"]["horizon"], "hidden_size": config.hidden_size, "layers": config.layers, "dropout": config.dropout})
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate, weight_decay=1e-4)
    training_tensors = tensors(train_split).tensors + (torch.tensor(onset_weights(train_split, config.onset_loss_weight), dtype=torch.float32),)
    loader = DataLoader(TensorDataset(*training_tensors), batch_size=min(config.batch_size, len(train_split["x"])), shuffle=True, generator=torch.Generator().manual_seed(config.seed))

    best_loss = float("inf")
    best_state = None
    stale_epochs = 0
    history = []
    for epoch in range(1, config.epochs + 1):
        model.train()
        batch_losses = []
        for x, target_state, target_attack, target_stage, onset_weight in loader:
            optimizer.zero_grad()
            loss, components = loss_for(model(x), target_state, target_attack, target_stage, config.state_loss_weight, attack_weight, stage_weight, onset_weight)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            batch_losses.append(float(loss.detach()))
        validation_loss = evaluate_loss(model, validation_split, config.state_loss_weight, attack_weight, stage_weight, config.onset_loss_weight)
        history.append({"epoch": epoch, "train_loss": float(np.mean(batch_losses)), "validation_loss": validation_loss})
        if validation_loss < best_loss - 1e-6:
            best_loss = validation_loss
            best_state = {key: value.detach().clone() for key, value in model.state_dict().items()}
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= config.patience:
                break
    model.load_state_dict(best_state)

    with torch.no_grad():
        validation_logits = model(torch.tensor(validation_split["x"], dtype=torch.float32))["attack_logits"].numpy()
    temperature = fit_temperature(validation_logits, (validation_split["y_attack"] > 0).astype(np.float32))
    validation_prediction = predictions(model, validation_split, temperature)
    test_prediction = predictions(model, test_split, temperature)
    ood_profile = fit_ood_profile(train_split["x"], validation_split["x"])
    validation_ood = ood_scores(validation_split["x"], ood_profile["lower"], ood_profile["upper"])
    test_ood = ood_scores(test_split["x"], ood_profile["lower"], ood_profile["upper"])
    threshold, validation_threshold_f1 = tune_threshold(validation_split, validation_prediction)
    sibling_name = output_dir.name.replace("-lstm", "-baseline")
    baseline_path = output_dir.parent / sibling_name / "metrics.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else None
    comparison = None
    if baseline:
        comparison = {
            "baseline_test_h1_f1": baseline["splits"]["test"]["binary"]["f1"],
            "lstm_test_h1_f1": metrics(test_split, test_prediction, threshold)["horizons"][0]["f1"],
            "note": "Both models use the fixed test partition; the LSTM threshold was selected only on validation data.",
        }
    report = {
        "model": f"multi_head_{config.architecture}_world_model",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "training": asdict(config),
        "model_config": model.configuration(),
        "best_epoch": min(history, key=lambda item: item["validation_loss"])["epoch"],
        "best_validation_loss": best_loss,
        "epochs_completed": len(history),
        "loss_weights": {"attack_positive": attack_weight.tolist(), "stage": stage_weight.tolist()},
        "onset_supervision": {
            "available": "anchor_attack" in train_split,
            "additional_loss_weight": config.onset_loss_weight,
            "train_onset_targets": int((onset_weights(train_split, 1.0) > 1.0).sum()),
            "validation_onset_targets": int((onset_weights(validation_split, 1.0) > 1.0).sum()),
            "test_onset_targets": int((onset_weights(test_split, 1.0) > 1.0).sum()),
        },
        "input_transform": INPUT_TRANSFORM,
        "normalization_clip": NORMALIZATION_CLIP,
        "feature_observed": {name: bool(feature_observed[index]) for index, name in enumerate(manifest["features"])},
        "validation_false_positive_rate_limit": MAX_VALIDATION_FPR,
        "temperature": temperature.tolist(),
        "ood": {
            "threshold": ood_profile["threshold"],
            "validation_flag_rate": float((validation_ood > ood_profile["threshold"]).mean()),
            "test_flag_rate": float((test_ood > ood_profile["threshold"]).mean()),
        },
        "decision_threshold": threshold,
        "validation_threshold_macro_f1": validation_threshold_f1,
        "validation": metrics(validation_split, validation_prediction, threshold),
        "test": metrics(test_split, test_prediction, threshold),
        "baseline_comparison": comparison,
        "integrated_gradients": attribution_summary(model, test_split, manifest["features"], temperature),
        "limitations": [
            *manifest.get("limitations", ["Dataset labels and partition scope must be checked before making performance claims."]),
            "Integrated Gradients reports model attribution relative to the training-mean baseline, not causality.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    torch.save({
        "state_dict": model.state_dict(),
        "feature_contract": manifest.get("feature_contract"),
        "dataset": manifest.get("dataset", "unspecified"),
        "target_definition": manifest.get("target_definition"),
        "model_config": model.configuration(),
        "normalization_mean": mean,
        "normalization_scale": scale,
        "input_transform": INPUT_TRANSFORM,
        "normalization_clip": NORMALIZATION_CLIP,
        "feature_observed": feature_observed,
        "temperature": temperature,
        "ood_lower": ood_profile["lower"],
        "ood_upper": ood_profile["upper"],
        "ood_threshold": ood_profile["threshold"],
        "features": manifest["features"],
        "stage_order": manifest["stage_order"],
        "sequence_length": manifest["config"]["sequence_length"],
        "decision_threshold": threshold,
    }, output_dir / "lstm.pt")
    (output_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output_dir / "history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the ShadowNet multi-head temporal world model.")
    parser.add_argument("--data", type=Path, default=Path("data/processed"))
    parser.add_argument("--output", type=Path, default=Path("data/models/lstm"))
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--architecture", choices=("lstm", "gru", "tcn", "transformer"), default="lstm")
    parser.add_argument("--hidden-size", type=int, default=64)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--onset-loss-weight", type=float, default=0.0, help="Additional loss multiplier for benign-to-attack transitions when anchor_attack labels exist.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    configuration = TrainingConfig(epochs=args.epochs, patience=args.patience, architecture=args.architecture, hidden_size=args.hidden_size, layers=args.layers, onset_loss_weight=args.onset_loss_weight)
    print(json.dumps(train(args.data, args.output, configuration), indent=2))
