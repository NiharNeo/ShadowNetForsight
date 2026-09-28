from __future__ import annotations

from collections import deque
from pathlib import Path
import json
import hashlib
import os
import re
from threading import RLock

import numpy as np
import torch

from pipeline.temporal_model import ForecastHeads, build_temporal_model
from pipeline.transforms import normalize_features
from pipeline.calibration import calibrate_logits, ood_scores
from pipeline.explainability import integrated_gradients


from pipeline.feature_contract import compatibility, PCAP_CONTRACT


class LSTMInferenceService:
    def __init__(self, checkpoint_path: Path, calibration_dir: Path | None = None) -> None:
        self.checkpoint_path = checkpoint_path
        self.checkpoint_sha256 = None
        self._predict_lock = RLock()
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
        self.feature_contract: str | None = None
        if self.available:
            try:
                self.checkpoint_sha256 = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
                expected = os.getenv("SHADOWNET_CHECKPOINT_SHA256")
                if expected and self.checkpoint_sha256 != expected:
                    raise ValueError("Checkpoint SHA-256 does not match the configured release")
                checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
                self.feature_contract = checkpoint.get("feature_contract")
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
                calibration_dir = calibration_dir or checkpoint_path.parent / "domain_calibrations"
                if calibration_dir.exists():
                    for path in calibration_dir.glob("*.json"):
                        profile = json.loads(path.read_text(encoding="utf-8"))
                        self.validate_calibration(profile)
                        self.domain_calibrations[str(profile["domain"])] = profile
            except Exception as error:
                self.available = False
                self.error = str(error)

    def validate_calibration(self, profile: dict) -> None:
        """Reject incompatible or numerically unsafe calibration before serving it."""
        if not isinstance(profile, dict) or profile.get("schema_version") != 2:
            raise ValueError("Calibration requires schema version 2")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", str(profile.get("domain", ""))):
            raise ValueError("Invalid calibration domain")
        if profile.get("checkpoint_sha256") != self.checkpoint_sha256:
            raise ValueError("Calibration checkpoint fingerprint mismatch or missing")
        if profile.get("fit_partition") != "validation":
            raise ValueError("Domain calibration must use the validation partition")
        for key, size in (("temperature", self.model.horizon), ("decision_threshold", self.model.horizon),
                          ("ood_lower", len(self.features)), ("ood_upper", len(self.features))):
            values = np.asarray(profile.get(key), dtype=np.float32)
            if values.shape != (size,) or not np.isfinite(values).all():
                raise ValueError(f"Invalid calibration {key}: expected {size} finite values")
            if key == "temperature" and (values <= 0).any():
                raise ValueError("Calibration temperatures must be positive")
            if key == "decision_threshold" and ((values < 0) | (values > 1)).any():
                raise ValueError("Calibration thresholds must lie between zero and one")
        if (np.asarray(profile["ood_lower"]) > np.asarray(profile["ood_upper"])).any():
            raise ValueError("Calibration OOD bounds are reversed")
        threshold = profile.get("ood_threshold")
        if not isinstance(threshold, (int, float)) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("Calibration OOD threshold must lie between zero and one")

    @property
    def sequence_length(self) -> int:
        return self._sequence_length

    def predict(self, states: list[dict[str, float]], domain: str | None = None) -> dict:
        with self._predict_lock:
            return self._predict(states, domain)

    def _predict(self, states: list[dict[str, float]], domain: str | None = None) -> dict:
        if not self.available or self.model is None or self.mean is None or self.scale is None:
            raise RuntimeError(self.error or f"Checkpoint unavailable: {self.checkpoint_path}")
        if len(states) < self.sequence_length:
            raise ValueError(f"Need {self.sequence_length} states; received {len(states)}")
        matrix = np.asarray([[state[name] for name in self.features] for state in states[-self.sequence_length:]], dtype=np.float32)
        if not np.isfinite(matrix).all():
            raise ValueError("Model inputs must be finite")
        if domain and domain not in self.domain_calibrations:
            raise ValueError("Unknown calibration domain")
        normalized = normalize_features(matrix[None, :, :], self.mean, self.scale, self.input_transform, self.normalization_clip)
        if self.feature_observed is not None:
            normalized[:, :, ~self.feature_observed] = 0.0
        profile = self.domain_calibrations.get(domain or "")
        temperature = np.asarray(profile["temperature"], dtype=np.float32) if profile else self.temperature
        thresholds = [float(value) for value in profile["decision_threshold"]] if profile else self.thresholds
        ood_lower = np.asarray(profile["ood_lower"], dtype=np.float32) if profile and "ood_lower" in profile else self.ood_lower
        ood_upper = np.asarray(profile["ood_upper"], dtype=np.float32) if profile and "ood_upper" in profile else self.ood_upper
        ood_threshold = float(profile["ood_threshold"]) if profile and "ood_threshold" in profile else self.ood_threshold
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
        ood_score = float(ood_scores(normalized, ood_lower, ood_upper)[0]) if ood_lower is not None and ood_upper is not None else 0.0
        ood_available = ood_lower is not None and ood_upper is not None and ood_threshold is not None
        is_ood = bool(ood_available and ood_score > ood_threshold)
        suppressed = is_ood or not ood_available
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
                "alert": False,
                "shadow_alert": bool(risk >= threshold and not suppressed),
            })
        return {
            "forecast": forecast,
            "sequence_states": self.sequence_length,
            "source": "trained_lstm",
            "operating_mode": "research_shadow_mode",
            "operational_alerting_enabled": False,
            "model_dataset": "CSE-CIC-IDS2018 five-day multi-family whole-day partitions",
            "calibration_domain": domain if profile else "global",
            "calibration_profile_applied": bool(profile),
            "unsupported_live_features": [name for name, observed in zip(self.features, self.feature_observed) if not observed] if self.feature_observed is not None else [],
            "explanation_method": "integrated_gradients_zero_mean_baseline",
            "feature_contributions": evidence,
            "temporal_contributions": temporal_evidence,
            "uncertainty": {
                "status": "unavailable" if not ood_available else ("out_of_distribution" if is_ood else "in_distribution"),
                "risk_band_method": "heuristic_stage_margin_not_statistical_interval",
                "claims_allowed": False,
                "ood_score": round(ood_score, 5),
                "ood_threshold": ood_threshold,
                "alerts_suppressed": True,
                "suppression_reasons": ["model_validation_incomplete"] + (["out_of_distribution"] if is_ood else ["ood_unavailable"] if not ood_available else []),
            },
        }


class ReplayInferenceSession:
    def __init__(self, service: LSTMInferenceService, domain: str | None = None, input_contract: str = PCAP_CONTRACT) -> None:
        self.input_contract = input_contract
        self.service = service
        self.domain = domain
        self.last_window_end: float | None = None
        self.states: deque[dict[str, float]] = deque(maxlen=service.sequence_length)

    def ingest(self, emitted_states: list[dict]) -> dict:
        for state in emitted_states:
            start, end = state.get("window_start"), state.get("window_end")
            if start is not None and end is not None:
                if abs((end - start) - 5) > 1e-6:
                    raise ValueError("Checkpoint requires five-second windows")
                if self.last_window_end is not None and abs(start - self.last_window_end) > 1e-6:
                    self.states.clear()
                self.last_window_end = end
            self.states.append(state["features"])
        ready = self.service.available and len(self.states) >= self.service.sequence_length
        result = {"model_available": self.service.available, "model_ready": ready, "warmup_states": len(self.states), "required_states": self.service.sequence_length, "forecast": []}
        if ready:
            result.update(self.service.predict(list(self.states), self.domain))
            result["feature_compatibility"] = compatibility(getattr(self.service, "feature_contract", None), self.input_contract)
            if not result["feature_compatibility"]["compatible"]:
                result["uncertainty"]["suppression_reasons"].append("feature_contract_unverified")
                for point in result["forecast"]:
                    point["shadow_alert"] = False
        elif self.service.error:
            result["model_error"] = self.service.error
        return result
