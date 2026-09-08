from __future__ import annotations

from collections import deque
from pathlib import Path
import json

import numpy as np
import torch

from pipeline.temporal_model import ForecastHeads, build_temporal_model
from pipeline.transforms import normalize_features
from pipeline.calibration import calibrate_logits, ood_scores
from pipeline.explainability import integrated_gradients


class LSTMInferenceService:
    def __init__(self, checkpoint_path: Path) -> None:
        self.checkpoint_path = checkpoint_path
        self.available = checkpoint_path.exists()
        self.error: str | None = None
        self.model: ForecastHeads | None = None
        self.features: list[str] = []
        self.stage_names: dict[int, str] = {}
        self.mean: np.ndarray | None = None
        self.scale: np.ndarray | None = None
        self._sequence_length = 12
        self.thresholds: list[float] = []
        self.input_transform = "identity"
        self.normalization_clip: float | None = None
        self.temperature: np.ndarray | None = None
        self.ood_lower: np.ndarray | None = None
        self.ood_upper: np.ndarray | None = None
        self.ood_threshold: float | None = None
        self.domain_calibrations: dict[str, dict] = {}
        self.feature_observed: np.ndarray | None = None
        if self.available:
            try:
                checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
                self.model = build_temporal_model(checkpoint["model_config"])
                self.model.load_state_dict(checkpoint["state_dict"])
                self.model.eval()
                self.features = checkpoint["features"]
                self.stage_names = {value: key for key, value in checkpoint["stage_order"].items()}
                self.mean = np.asarray(checkpoint["normalization_mean"], dtype=np.float32)
                self.scale = np.asarray(checkpoint["normalization_scale"], dtype=np.float32)
                self._sequence_length = int(checkpoint.get("sequence_length", 12))
                raw_threshold = checkpoint.get("decision_threshold", 0.5)
                self.thresholds = [float(raw_threshold)] * self.model.horizon if np.isscalar(raw_threshold) else [float(value) for value in raw_threshold]
                self.input_transform = checkpoint.get("input_transform", "identity")
                self.normalization_clip = checkpoint.get("normalization_clip")
                self.temperature = np.asarray(checkpoint.get("temperature", np.ones(self.model.horizon)), dtype=np.float32)
                self.feature_observed = np.asarray(checkpoint.get("feature_observed", np.ones(len(self.features), dtype=bool)), dtype=bool)
                if "ood_lower" in checkpoint:
                    self.ood_lower = np.asarray(checkpoint["ood_lower"], dtype=np.float32)
                    self.ood_upper = np.asarray(checkpoint["ood_upper"], dtype=np.float32)
                    self.ood_threshold = float(checkpoint["ood_threshold"])
                calibration_dir = checkpoint_path.parent / "domain_calibrations"
                if calibration_dir.exists():
                    for path in calibration_dir.glob("*.json"):
                        profile = json.loads(path.read_text(encoding="utf-8"))
                        if profile.get("fit_partition") != "validation":
                            raise ValueError(f"Domain calibration must be validation-only: {path}")
                        self.domain_calibrations[str(profile["domain"])] = profile
            except Exception as error:
                self.available = False
                self.error = str(error)

    @property
    def sequence_length(self) -> int:
        return self._sequence_length

    def predict(self, states: list[dict[str, float]], domain: str | None = None) -> dict:
        if not self.available or self.model is None or self.mean is None or self.scale is None:
            raise RuntimeError(self.error or f"Checkpoint unavailable: {self.checkpoint_path}")
        if len(states) < self.sequence_length:
            raise ValueError(f"Need {self.sequence_length} states; received {len(states)}")
        matrix = np.asarray([[state[name] for name in self.features] for state in states[-self.sequence_length:]], dtype=np.float32)
        normalized = normalize_features(matrix[None, :, :], self.mean, self.scale, self.input_transform, self.normalization_clip)
        if self.feature_observed is not None:
            normalized[:, :, ~self.feature_observed] = 0.0
        profile = self.domain_calibrations.get(domain or "")
        temperature = np.asarray(profile["temperature"], dtype=np.float32) if profile else self.temperature
        thresholds = [float(value) for value in profile["decision_threshold"]] if profile else self.thresholds
        with torch.no_grad():
            output = self.model(torch.tensor(normalized, dtype=torch.float32))
            risks = torch.sigmoid(calibrate_logits(output["attack_logits"], temperature))[0].numpy()
            stage_probability = torch.softmax(output["stage_logits"], dim=-1)[0].numpy()
        explanation = integrated_gradients(self.model, normalized, temperature, horizon=0)
        importance = explanation["feature_importance"]
        total_importance = float(importance.sum())
        order = np.argsort(importance)[::-1][:5]
        evidence = [
            {"feature": self.features[index], "contribution": round(float(importance[index] / max(total_importance, 1e-12) * 100.0), 2)}
            for index in order
        ]
        time_importance = explanation["time_importance"]
        time_total = float(time_importance.sum())
        temporal_evidence = [
            {"history_offset_seconds": -5 * (len(time_importance) - index - 1), "contribution": round(float(value / max(time_total, 1e-12) * 100.0), 2)}
            for index, value in enumerate(time_importance)
        ]
        ood_score = float(ood_scores(normalized, self.ood_lower, self.ood_upper)[0]) if self.ood_lower is not None and self.ood_upper is not None else 0.0
        is_ood = bool(self.ood_threshold is not None and ood_score > self.ood_threshold)
        forecast = []
        for index, risk in enumerate(risks):
            stage_id = int(stage_probability[index].argmax())
            confidence = float(stage_probability[index, stage_id])
            margin = (1.0 - confidence) * 30.0
            risk_percent = float(risk * 100.0)
            threshold = thresholds[index] if index < len(thresholds) else 0.5
            forecast.append({
                "step": index + 1,
                "offset_seconds": (index + 1) * 5,
                "risk": round(risk_percent, 2),
                "risk_low": round(max(0.0, risk_percent - margin), 2),
                "risk_high": round(min(100.0, risk_percent + margin), 2),
                "stage_id": stage_id,
                "stage": self.stage_names.get(stage_id, "Unknown"),
                "confidence": round(confidence * 100.0, 2),
                "threshold": round(threshold * 100.0, 4),
                "alert": bool(risk >= threshold and not is_ood),
            })
        return {
            "forecast": forecast,
            "sequence_states": self.sequence_length,
            "source": "trained_lstm",
            "model_dataset": "CSE-CIC-IDS2018 five-day multi-family whole-day partitions",
            "calibration_domain": domain if profile else "global",
            "calibration_profile_applied": bool(profile),
            "unsupported_live_features": [name for name, observed in zip(self.features, self.feature_observed) if not observed] if self.feature_observed is not None else [],
            "explanation_method": "integrated_gradients_zero_mean_baseline",
            "feature_contributions": evidence,
            "temporal_contributions": temporal_evidence,
            "uncertainty": {
                "status": "out_of_distribution" if is_ood else "in_distribution",
                "ood_score": round(ood_score, 5),
                "ood_threshold": self.ood_threshold,
                "alerts_suppressed": is_ood,
            },
        }


class ReplayInferenceSession:
    def __init__(self, service: LSTMInferenceService, domain: str | None = None) -> None:
        self.service = service
        self.domain = domain
        self.states: deque[dict[str, float]] = deque(maxlen=service.sequence_length)

    def ingest(self, emitted_states: list[dict]) -> dict:
        for state in emitted_states:
            self.states.append(state["features"])
        ready = self.service.available and len(self.states) >= self.service.sequence_length
        result = {"model_available": self.service.available, "model_ready": ready, "warmup_states": len(self.states), "required_states": self.service.sequence_length, "forecast": []}
        if ready:
            result.update(self.service.predict(list(self.states), self.domain))
        elif self.service.error:
            result["model_error"] = self.service.error
        return result
