from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def load_manifest(processed_dir: Path) -> dict:
    path = processed_dir / "manifest.json"
    if not path.exists():
        raise FileNotFoundError(f"Dataset manifest not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_split(processed_dir: Path, name: str) -> dict[str, np.ndarray]:
    path = processed_dir / f"{name}.npz"
    if not path.exists():
        raise FileNotFoundError(f"Dataset split not found: {path}")
    with np.load(path, allow_pickle=False) as archive:
        return {key: archive[key] for key in archive.files}


def current_state(split: dict[str, np.ndarray]) -> np.ndarray:
    """Static baseline sees only S_t, never the preceding temporal sequence."""
    return split["x"][:, -1, :]


def binary_target(split: dict[str, np.ndarray]) -> np.ndarray:
    return (split["y_attack"][:, 0] > 0).astype(np.int64)


def stage_target(split: dict[str, np.ndarray]) -> np.ndarray:
    return split["y_stage"][:, 0].astype(np.int64)


def classifier(seed: int) -> Pipeline:
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)),
    ])


def fit_or_dummy(x: np.ndarray, y: np.ndarray, seed: int) -> Pipeline:
    model = classifier(seed)
    if np.unique(y).size < 2:
        model = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", DummyClassifier(strategy="most_frequent")),
        ])
    return model.fit(x, y)


def positive_probability(model: Pipeline, x: np.ndarray) -> np.ndarray:
    probabilities = model.predict_proba(x)
    classes = model.named_steps["model"].classes_
    match = np.flatnonzero(classes == 1)
    return probabilities[:, match[0]] if len(match) else np.zeros(len(x), dtype=float)


def safe_auc(metric, y_true: np.ndarray, score: np.ndarray) -> float | None:
    if np.unique(y_true).size < 2:
        return None
    return float(metric(y_true, score))


def false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, _, _ = matrix.ravel()
    return float(fp / max(fp + tn, 1))


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, score: np.ndarray) -> dict:
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": false_positive_rate(y_true, y_pred),
        "roc_auc": safe_auc(roc_auc_score, y_true, score),
        "pr_auc": safe_auc(average_precision_score, y_true, score),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "support": int(len(y_true)),
        "positive_support": int(y_true.sum()),
    }


def stage_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: list[int]) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "support": int(len(y_true)),
    }


def feature_importance(model: Pipeline, features: list[str]) -> list[dict]:
    estimator = model.named_steps["model"]
    if not hasattr(estimator, "coef_"):
        return []
    coefficients = np.abs(estimator.coef_).mean(axis=0)
    order = np.argsort(coefficients)[::-1]
    return [{"feature": features[index], "importance": float(coefficients[index])} for index in order]


def train(processed_dir: Path, output_dir: Path, seed: int = 42) -> dict:
    manifest = load_manifest(processed_dir)
    train_split = load_split(processed_dir, "train")
    validation_split = load_split(processed_dir, "validation")
    test_split = load_split(processed_dir, "test")

    x_train = current_state(train_split)
    y_train_binary = binary_target(train_split)
    y_train_stage = stage_target(train_split)

    binary_model = fit_or_dummy(x_train, y_train_binary, seed)
    stage_model = fit_or_dummy(x_train, y_train_stage, seed)

    report = {
        "model": "static_logistic_regression_baseline",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "input_contract": "Only the latest state S_t is used to predict t+1.",
        "dataset_config": manifest["config"],
        "features": manifest["features"],
        "train_support": int(len(x_train)),
        "train_class_counts": {
            "binary": {str(value): int((y_train_binary == value).sum()) for value in np.unique(y_train_binary)},
            "stage": {str(value): int((y_train_stage == value).sum()) for value in np.unique(y_train_stage)},
        },
        "splits": {},
        "feature_importance": feature_importance(binary_model, manifest["features"]),
        "limitations": [
            "The baseline does not model sequences or perform K-step rollout.",
            "CIC attack stages are documented proxy labels rather than native MITRE progression ground truth.",
            "Metrics from generated demo data validate plumbing only and are not research claims.",
        ],
    }

    for name, split in (("validation", validation_split), ("test", test_split)):
        x = current_state(split)
        y_binary = binary_target(split)
        y_stage = stage_target(split)
        binary_prediction = binary_model.predict(x)
        stage_prediction = stage_model.predict(x)
        report["splits"][name] = {
            "binary": binary_metrics(y_binary, binary_prediction, positive_probability(binary_model, x)),
            "next_stage": stage_metrics(y_stage, stage_prediction, sorted(manifest["stage_order"].values())),
            "time_range": [str(split["anchor_time"][0]), str(split["anchor_time"][-1])],
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "binary_model": binary_model,
            "stage_model": stage_model,
            "features": manifest["features"],
            "stage_order": manifest["stage_order"],
            "dataset_config": manifest["config"],
        },
        output_dir / "baseline.joblib",
    )
    (output_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the static ShadowNet baseline on chronological network states.")
    parser.add_argument("--data", type=Path, default=Path("data/processed"))
    parser.add_argument("--output", type=Path, default=Path("data/models/baseline"))
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(json.dumps(train(args.data, args.output, args.seed), indent=2))
