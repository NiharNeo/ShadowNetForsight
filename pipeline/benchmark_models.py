from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from pipeline.train_lstm import TrainingConfig, train


CANDIDATES = [
    (architecture, hidden_size, layers)
    for architecture in ("lstm", "gru", "tcn", "transformer")
    for hidden_size, layers in ((32, 1), (64, 2))
]


def benchmark(data_dir: Path, output_dir: Path, epochs: int, patience: int) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for architecture, hidden_size, layers in CANDIDATES:
        name = f"{architecture}-h{hidden_size}-l{layers}"
        config = TrainingConfig(architecture=architecture, hidden_size=hidden_size, layers=layers, epochs=epochs, patience=patience)
        report = train(data_dir, output_dir / name, config)
        validation = report["validation"]
        mean_fpr = sum(item["false_positive_rate"] for item in validation["horizons"]) / len(validation["horizons"])
        results.append({
            "candidate": name,
            "config": asdict(config),
            "validation_attack_f1": validation["attack_f1_macro_over_horizons"],
            "validation_mean_fpr": mean_fpr,
            "validation_stage_accuracy": validation["stage_accuracy_macro_over_horizons"],
            "validation_future_state_mae": validation["future_state_mae_normalized"],
            "checkpoint": str(output_dir / name / "lstm.pt"),
        })
    ranking = sorted(results, key=lambda item: (-item["validation_attack_f1"], item["validation_mean_fpr"], item["validation_future_state_mae"]))
    winner = ranking[0]
    shutil.copy2(winner["checkpoint"], output_dir / "best.pt")
    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "selection_protocol": "Architecture and hyperparameters selected only by the fixed whole-day validation split under the shared 5% FPR budget.",
        "winner": winner,
        "ranking": ranking,
        "test_metrics_excluded_from_selection": True,
    }
    (output_dir / "benchmark.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Time-aware ShadowNet temporal-architecture benchmark.")
    parser.add_argument("--data", type=Path, default=Path("data/processed-cic2018-multiday"))
    parser.add_argument("--output", type=Path, default=Path("models/phase2-benchmark"))
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--patience", type=int, default=6)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.data, args.output, args.epochs, args.patience), indent=2))
