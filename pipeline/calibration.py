from __future__ import annotations

import numpy as np
import torch
from torch import nn


def fit_temperature(logits: np.ndarray, truth: np.ndarray, steps: int = 300) -> np.ndarray:
    """Fit one positive temperature per horizon using validation data only."""
    logits_tensor = torch.tensor(logits, dtype=torch.float32)
    truth_tensor = torch.tensor(truth, dtype=torch.float32)
    log_temperature = nn.Parameter(torch.zeros(logits.shape[1], dtype=torch.float32))
    optimizer = torch.optim.Adam([log_temperature], lr=0.05)
    for _ in range(steps):
        optimizer.zero_grad()
        temperature = log_temperature.exp().clamp(0.05, 20.0)
        loss = nn.functional.binary_cross_entropy_with_logits(logits_tensor / temperature, truth_tensor)
        loss.backward()
        optimizer.step()
    return log_temperature.detach().exp().clamp(0.05, 20.0).numpy()


def calibrate_logits(logits: torch.Tensor, temperature: np.ndarray | list[float] | None) -> torch.Tensor:
    if temperature is None:
        return logits
    values = torch.as_tensor(temperature, dtype=logits.dtype, device=logits.device).reshape(1, -1)
    return logits / values


def fit_ood_profile(train_x: np.ndarray, validation_x: np.ndarray, feature_quantile: float = 0.995, score_quantile: float = 0.99) -> dict:
    lower = np.quantile(train_x, 1.0 - feature_quantile, axis=(0, 1)).astype(np.float32)
    upper = np.quantile(train_x, feature_quantile, axis=(0, 1)).astype(np.float32)
    validation_scores = ood_scores(validation_x, lower, upper)
    return {
        "lower": lower,
        "upper": upper,
        "threshold": float(np.quantile(validation_scores, score_quantile)),
        "feature_quantile": feature_quantile,
        "validation_score_quantile": score_quantile,
    }


def ood_scores(x: np.ndarray, lower: np.ndarray, upper: np.ndarray) -> np.ndarray:
    outside = (x < lower.reshape(1, 1, -1)) | (x > upper.reshape(1, 1, -1))
    return outside.mean(axis=(1, 2)).astype(np.float32)
