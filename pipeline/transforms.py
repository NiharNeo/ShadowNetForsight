from __future__ import annotations

import numpy as np


def transform_features(values: np.ndarray, kind: str = "identity") -> np.ndarray:
    array = np.asarray(values, dtype=np.float32)
    if kind == "identity":
        return array
    if kind == "log1p_nonnegative":
        return np.log1p(np.clip(array, 0.0, None))
    raise ValueError(f"Unknown input transform: {kind}")


def normalize_features(values: np.ndarray, mean: np.ndarray, scale: np.ndarray, kind: str = "identity", clip: float | None = None) -> np.ndarray:
    normalized = (transform_features(values, kind) - mean) / scale
    return np.clip(normalized, -clip, clip) if clip is not None else normalized
