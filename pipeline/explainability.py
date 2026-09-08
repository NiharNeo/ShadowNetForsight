from __future__ import annotations

import numpy as np
import torch

from pipeline.calibration import calibrate_logits


def integrated_gradients(model: torch.nn.Module, sequence: np.ndarray, temperature: np.ndarray | None = None, horizon: int = 0, steps: int = 24) -> dict[str, np.ndarray]:
    """Integrated Gradients from a zero (training-mean) baseline."""
    values = torch.tensor(sequence, dtype=torch.float32)
    baseline = torch.zeros_like(values)
    gradient_sum = torch.zeros_like(values)
    for alpha in torch.linspace(0.0, 1.0, steps + 1)[1:]:
        interpolated = (baseline + alpha * (values - baseline)).detach().requires_grad_(True)
        logits = model(interpolated)["attack_logits"]
        probability = torch.sigmoid(calibrate_logits(logits, temperature))[0, horizon]
        gradient = torch.autograd.grad(probability, interpolated)[0]
        gradient_sum += gradient.detach()
    attribution = ((values - baseline) * gradient_sum / steps).detach().numpy()[0]
    absolute = np.abs(attribution)
    return {
        "attribution": attribution,
        "feature_importance": absolute.sum(axis=0),
        "time_importance": absolute.sum(axis=1),
    }
