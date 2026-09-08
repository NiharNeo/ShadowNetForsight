from __future__ import annotations

import math
import torch
from torch import nn


class ForecastHeads(nn.Module):
    def __init__(self, feature_count: int, stage_count: int, horizon: int, hidden_size: int, layers: int, dropout: float, architecture: str) -> None:
        super().__init__()
        self.feature_count, self.stage_count, self.horizon = feature_count, stage_count, horizon
        self.hidden_size, self.layers, self.dropout, self.architecture = hidden_size, layers, dropout, architecture
        self.shared = nn.Sequential(nn.LayerNorm(hidden_size), nn.Linear(hidden_size, hidden_size), nn.GELU())
        self.attack_head = nn.Linear(hidden_size, horizon)
        self.stage_head = nn.Linear(hidden_size, horizon * stage_count)
        self.state_head = nn.Linear(hidden_size, horizon * feature_count)

    def heads(self, representation: torch.Tensor) -> dict[str, torch.Tensor]:
        representation = self.shared(representation)
        return {
            "attack_logits": self.attack_head(representation),
            "stage_logits": self.stage_head(representation).view(-1, self.horizon, self.stage_count),
            "future_state": self.state_head(representation).view(-1, self.horizon, self.feature_count),
        }

    def configuration(self) -> dict:
        return {"architecture": self.architecture, "feature_count": self.feature_count, "stage_count": self.stage_count, "horizon": self.horizon, "hidden_size": self.hidden_size, "layers": self.layers, "dropout": self.dropout}


class ForeSightLSTM(ForecastHeads):
    def __init__(self, feature_count: int, stage_count: int, horizon: int, hidden_size: int = 64, layers: int = 2, dropout: float = 0.2, architecture: str = "lstm") -> None:
        super().__init__(feature_count, stage_count, horizon, hidden_size, layers, dropout, "lstm")
        self.encoder = nn.LSTM(feature_count, hidden_size, layers, dropout=dropout if layers > 1 else 0.0, batch_first=True)

    def forward(self, sequence: torch.Tensor) -> dict[str, torch.Tensor]:
        encoded, _ = self.encoder(sequence)
        return self.heads(encoded[:, -1, :])


class ForeSightGRU(ForecastHeads):
    def __init__(self, feature_count: int, stage_count: int, horizon: int, hidden_size: int = 64, layers: int = 2, dropout: float = 0.2, architecture: str = "gru") -> None:
        super().__init__(feature_count, stage_count, horizon, hidden_size, layers, dropout, "gru")
        self.encoder = nn.GRU(feature_count, hidden_size, layers, dropout=dropout if layers > 1 else 0.0, batch_first=True)

    def forward(self, sequence: torch.Tensor) -> dict[str, torch.Tensor]:
        encoded, _ = self.encoder(sequence)
        return self.heads(encoded[:, -1, :])


class CausalConvBlock(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, dilation: int, dropout: float) -> None:
        super().__init__()
        self.padding = 2 * dilation
        self.conv = nn.Conv1d(in_channels, out_channels, kernel_size=3, padding=self.padding, dilation=dilation)
        self.activation = nn.GELU()
        self.dropout = nn.Dropout(dropout)

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        convolved = self.conv(values)
        return self.dropout(self.activation(convolved[:, :, :-self.padding]))


class ForeSightTCN(ForecastHeads):
    def __init__(self, feature_count: int, stage_count: int, horizon: int, hidden_size: int = 64, layers: int = 2, dropout: float = 0.2, architecture: str = "tcn") -> None:
        super().__init__(feature_count, stage_count, horizon, hidden_size, layers, dropout, "tcn")
        blocks = []
        in_channels = feature_count
        for index in range(layers):
            dilation = 2**index
            blocks.append(CausalConvBlock(in_channels, hidden_size, dilation, dropout))
            in_channels = hidden_size
        self.encoder = nn.Sequential(*blocks)

    def forward(self, sequence: torch.Tensor) -> dict[str, torch.Tensor]:
        encoded = self.encoder(sequence.transpose(1, 2))
        return self.heads(encoded[:, :, -1])


class ForeSightTransformer(ForecastHeads):
    def __init__(self, feature_count: int, stage_count: int, horizon: int, hidden_size: int = 64, layers: int = 2, dropout: float = 0.2, architecture: str = "transformer") -> None:
        super().__init__(feature_count, stage_count, horizon, hidden_size, layers, dropout, "transformer")
        self.projection = nn.Linear(feature_count, hidden_size)
        heads = next(value for value in (8, 4, 2, 1) if hidden_size % value == 0)
        layer = nn.TransformerEncoderLayer(hidden_size, heads, hidden_size * 4, dropout, batch_first=True, norm_first=True)
        self.encoder = nn.TransformerEncoder(layer, layers)

    def forward(self, sequence: torch.Tensor) -> dict[str, torch.Tensor]:
        positions = torch.arange(sequence.shape[1], device=sequence.device, dtype=sequence.dtype).reshape(1, -1, 1)
        frequencies = torch.exp(torch.arange(0, self.hidden_size, 2, device=sequence.device, dtype=sequence.dtype) * (-math.log(10000.0) / self.hidden_size))
        positional = torch.zeros(1, sequence.shape[1], self.hidden_size, device=sequence.device, dtype=sequence.dtype)
        positional[:, :, 0::2] = torch.sin(positions * frequencies)
        positional[:, :, 1::2] = torch.cos(positions * frequencies[: positional[:, :, 1::2].shape[-1]])
        encoded = self.encoder(self.projection(sequence) + positional)
        return self.heads(encoded[:, -1, :])


def build_temporal_model(configuration: dict) -> ForecastHeads:
    config = dict(configuration)
    architecture = config.pop("architecture", "lstm")
    classes = {"lstm": ForeSightLSTM, "gru": ForeSightGRU, "tcn": ForeSightTCN, "transformer": ForeSightTransformer}
    if architecture not in classes:
        raise ValueError(f"Unsupported temporal architecture: {architecture}")
    return classes[architecture](architecture=architecture, **config)
