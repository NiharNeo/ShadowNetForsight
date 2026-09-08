from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from pipeline.stage_mapping import LABEL_RULES, STAGE_ORDER, map_label


ALIASES = {
    "timestamp": ["timestamp", "time stamp", "date time", "starttime", "start time"],
    "label": ["label", "class", "attack"],
    "src_ip": ["src ip", "source ip", "srcip", "srcaddr"],
    "dst_ip": ["dst ip", "destination ip", "dstip", "dstaddr"],
    "dst_port": ["dst port", "destination port", "dstport", "dport"],
    "protocol": ["protocol", "proto"],
    "duration": ["flow duration", "duration", "dur"],
    "fwd_packets": ["tot fwd pkts", "total fwd packets", "fwd packets", "totpkts"],
    "bwd_packets": ["tot bwd pkts", "total backward packets", "bwd packets"],
    "fwd_bytes": ["totlen fwd pkts", "total length of fwd packets", "fwd bytes", "srcbytes"],
    "bwd_bytes": ["totlen bwd pkts", "total length of bwd packets", "bwd bytes"],
    "total_bytes": ["totbytes", "total bytes"],
    "iat_mean": ["flow iat mean", "iat mean"],
    "syn_count": ["syn flag cnt", "syn flag count"],
    "ack_count": ["ack flag cnt", "ack flag count"],
    "rst_count": ["rst flag cnt", "rst flag count"],
    "psh_count": ["psh flag cnt", "psh flag count"],
    "fin_count": ["fin flag cnt", "fin flag count"],
    "urg_count": ["urg flag cnt", "urg flag count"],
    "ttl_mean": ["ttl", "ttl mean"],
    "ttl_variance": ["ttl variance", "ttl var"],
    "tcp_window_mean": ["tcp window", "window size", "init win bytes forward"],
    "fragment_count": ["fragment count", "ip fragments"],
    "payload_size_mean": ["packet length mean", "payload size mean"],
    "payload_size_std": ["packet length std", "payload size std"],
    "retransmission_count": ["retransmission count", "retransmissions"],
}

FEATURES = [
    "flow_count",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_dst_ports",
    "protocol_count",
    "duration_mean",
    "fwd_packets_sum",
    "bwd_packets_sum",
    "bytes_sum",
    "iat_mean",
    "syn_count",
    "ack_count",
    "rst_count",
    "psh_count",
    "syn_ack_ratio",
    "unique_host_edges",
    "max_source_fanout",
    "max_destination_fanin",
    "east_west_ratio",
    "failed_auth_count",
    "identity_reuse_count",
    "fin_count", "urg_count", "ttl_mean", "ttl_variance", "tcp_window_mean",
    "fragment_count", "payload_size_mean", "payload_size_std", "retransmission_count",
    "sequential_port_ratio",
]


@dataclass(frozen=True)
class BuildConfig:
    window_seconds: int = 5
    sequence_length: int = 12
    horizon: int = 3
    train_fraction: float = 0.70
    validation_fraction: float = 0.15


def _canonical(value: object) -> str:
    return " ".join(str(value).strip().lower().replace("_", " ").replace("/", " ").split())


def resolve_columns(columns: Iterable[object]) -> dict[str, str]:
    available = {_canonical(column): str(column) for column in columns}
    resolved: dict[str, str] = {}
    for target, aliases in ALIASES.items():
        match = next((available[_canonical(alias)] for alias in aliases if _canonical(alias) in available), None)
        if match:
            resolved[target] = match
    missing = {"timestamp", "label"} - resolved.keys()
    if missing:
        raise ValueError(f"Missing required CIC columns: {sorted(missing)}. Found: {sorted(map(str, columns))}")
    return resolved


def _numeric(frame: pd.DataFrame, column: str | None) -> pd.Series:
    if column is None:
        return pd.Series(0.0, index=frame.index, dtype="float64")
    return pd.to_numeric(frame[column], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)


def load_flows(paths: list[Path]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for path in paths:
        frame = pd.read_csv(path, low_memory=False)
        columns = resolve_columns(frame.columns)
        clean = pd.DataFrame(index=frame.index)
        clean["timestamp"] = pd.to_datetime(frame[columns["timestamp"]], errors="coerce", dayfirst=True, format="mixed")
        clean["raw_label"] = frame[columns["label"]].fillna("Unknown").astype(str).str.strip()
        for name in ("src_ip", "dst_ip", "dst_port", "protocol"):
            source = columns.get(name)
            clean[name] = frame[source].fillna("unknown").astype(str) if source else "unknown"
        for name in ("duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "iat_mean", "syn_count", "ack_count", "rst_count", "psh_count", "fin_count", "urg_count", "ttl_mean", "ttl_variance", "tcp_window_mean", "fragment_count", "payload_size_mean", "payload_size_std", "retransmission_count"):
            clean[name] = _numeric(frame, columns.get(name))
        if "total_bytes" in columns:
            total_bytes = _numeric(frame, columns["total_bytes"])
            clean["bwd_bytes"] = (total_bytes - clean["fwd_bytes"]).clip(lower=0.0)
        clean = clean.dropna(subset=["timestamp"])
        # Some official CIC day files contain a handful of malformed 1970
        # timestamps among more than a million same-day rows. When one calendar
        # day overwhelmingly dominates a file, discard those date outliers so
        # they cannot create decades of empty resampling bins.
        dates = clean["timestamp"].dt.normalize()
        if not dates.empty:
            dominant_date = dates.mode().iat[0]
            dominant_fraction = float((dates == dominant_date).mean())
            if dominant_fraction >= 0.95:
                clean = clean.loc[dates == dominant_date]
        frames.append(clean)
    if not frames:
        raise ValueError("No input CSV files were supplied.")
    flows = pd.concat(frames, ignore_index=True).sort_values("timestamp", kind="stable").reset_index(drop=True)
    if flows.empty:
        raise ValueError("No valid timestamped rows remain after parsing.")
    mapped = flows["raw_label"].map(map_label)
    flows["stage"] = mapped.map(lambda pair: pair[0])
    flows["mapping_rationale"] = mapped.map(lambda pair: pair[1])
    flows["is_attack"] = (flows["stage"] != "Normal").astype("float32")
    return flows


def aggregate_windows(flows: pd.DataFrame, seconds: int) -> pd.DataFrame:
    work = flows.copy()
    for name in ("fin_count", "urg_count", "ttl_mean", "ttl_variance", "tcp_window_mean", "fragment_count", "payload_size_mean", "payload_size_std", "retransmission_count"):
        if name not in work:
            work[name] = 0.0
    origin = work["timestamp"].min()
    offsets = ((work["timestamp"] - origin).dt.total_seconds() // seconds).astype("int64")
    work["window_start"] = origin + pd.to_timedelta(offsets * seconds, unit="s")
    work["stage_id"] = work["stage"].map(STAGE_ORDER).astype("int64")
    work["bytes"] = work["fwd_bytes"] + work["bwd_bytes"]
    work["host_edge"] = work["src_ip"].astype(str) + "→" + work["dst_ip"].astype(str)
    private_pattern = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
    work["east_west"] = (work["src_ip"].astype(str).str.match(private_pattern) & work["dst_ip"].astype(str).str.match(private_pattern)).astype(float)
    grouped = work.groupby("window_start", sort=True, observed=True)
    windows = grouped.agg(
        flow_count=("stage", "size"),
        unique_src_ips=("src_ip", "nunique"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        protocol_count=("protocol", "nunique"),
        duration_mean=("duration", "mean"),
        fwd_packets_sum=("fwd_packets", "sum"),
        bwd_packets_sum=("bwd_packets", "sum"),
        bytes_sum=("bytes", "sum"),
        iat_mean=("iat_mean", "mean"),
        syn_count=("syn_count", "sum"),
        ack_count=("ack_count", "sum"),
        rst_count=("rst_count", "sum"),
        psh_count=("psh_count", "sum"),
        attack_fraction=("is_attack", "mean"),
        stage_id=("stage_id", "max"),
        dominant_label=("raw_label", lambda values: values.mode().iat[0]),
        unique_host_edges=("host_edge", "nunique"),
        east_west_ratio=("east_west", "mean"),
        fin_count=("fin_count", "sum"), urg_count=("urg_count", "sum"),
        ttl_mean=("ttl_mean", "mean"), ttl_variance=("ttl_variance", "mean"),
        tcp_window_mean=("tcp_window_mean", "mean"), fragment_count=("fragment_count", "sum"),
        payload_size_mean=("payload_size_mean", "mean"), payload_size_std=("payload_size_std", "mean"),
        retransmission_count=("retransmission_count", "sum"),
    ).reset_index()
    source_fanout = work.groupby(["window_start", "src_ip"], observed=True)["dst_ip"].nunique().groupby(level=0).max()
    destination_fanin = work.groupby(["window_start", "dst_ip"], observed=True)["src_ip"].nunique().groupby(level=0).max()
    windows["max_source_fanout"] = windows["window_start"].map(source_fanout).fillna(0)
    windows["max_destination_fanin"] = windows["window_start"].map(destination_fanin).fillna(0)
    # CICFlowMeter has no authentication identity fields. These remain explicit
    # zeros instead of fabricated labels; Cowrie telemetry supplies them live.
    windows["failed_auth_count"] = 0.0
    windows["identity_reuse_count"] = 0.0
    windows["sequential_port_ratio"] = 0.0
    inverse_stages = {value: key for key, value in STAGE_ORDER.items()}
    windows["stage"] = windows["stage_id"].map(inverse_stages)
    windows["syn_ack_ratio"] = windows["syn_count"] / windows["ack_count"].clip(lower=1.0)
    return windows


def make_sequences(windows: pd.DataFrame, config: BuildConfig) -> dict[str, np.ndarray]:
    feature_matrix = windows[FEATURES].to_numpy(dtype=np.float32)
    stage = windows["stage_id"].to_numpy(dtype=np.int64)
    attack = windows["attack_fraction"].to_numpy(dtype=np.float32)
    count = len(windows) - config.sequence_length - config.horizon + 1
    if count <= 0:
        raise ValueError(f"Need at least {config.sequence_length + config.horizon} windows; found {len(windows)}.")
    x = np.stack([feature_matrix[i : i + config.sequence_length] for i in range(count)])
    y_stage = np.stack([stage[i + config.sequence_length : i + config.sequence_length + config.horizon] for i in range(count)])
    y_attack = np.stack([attack[i + config.sequence_length : i + config.sequence_length + config.horizon] for i in range(count)])
    y_state = np.stack([feature_matrix[i + config.sequence_length : i + config.sequence_length + config.horizon] for i in range(count)])
    anchor_values = windows["window_start"].iloc[config.sequence_length - 1 : config.sequence_length - 1 + count].astype(str).tolist()
    anchors = np.asarray(anchor_values, dtype="U32")
    return {"x": x, "y_state": y_state, "y_stage": y_stage, "y_attack": y_attack, "anchor_time": anchors}


def chronological_slices(count: int, config: BuildConfig) -> dict[str, slice]:
    train_end = int(count * config.train_fraction)
    validation_end = int(count * (config.train_fraction + config.validation_fraction))
    if not 0 < train_end < validation_end < count:
        raise ValueError("Dataset is too small for non-empty chronological train/validation/test splits.")
    return {"train": slice(0, train_end), "validation": slice(train_end, validation_end), "test": slice(validation_end, count)}


def build(paths: list[Path], output_dir: Path, config: BuildConfig) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    flows = load_flows(paths)
    windows = aggregate_windows(flows, config.window_seconds)
    sequences = make_sequences(windows, config)
    slices = chronological_slices(len(sequences["x"]), config)
    windows.to_csv(output_dir / "network_states.csv", index=False)
    for name, split in slices.items():
        np.savez_compressed(output_dir / f"{name}.npz", **{key: value[split] for key, value in sequences.items()})
    manifest = {
        "config": asdict(config),
        "inputs": [str(path) for path in paths],
        "flow_rows": len(flows),
        "network_states": len(windows),
        "sequences": len(sequences["x"]),
        "split_sizes": {name: split.stop - split.start for name, split in slices.items()},
        "features": FEATURES,
        "stage_order": STAGE_ORDER,
        "label_rules": [{"pattern": pattern, "stage": stage, "rationale": rationale} for pattern, stage, rationale in LABEL_RULES],
        "warning": "Stage labels are documented proxies derived from CIC traffic-family labels, not native MITRE ground truth.",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build chronological ShadowNet network-state sequences from CIC CSV files.")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=Path("data/processed"))
    parser.add_argument("--window-seconds", type=int, default=5)
    parser.add_argument("--sequence-length", type=int, default=12)
    parser.add_argument("--horizon", type=int, default=3)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    configuration = BuildConfig(window_seconds=args.window_seconds, sequence_length=args.sequence_length, horizon=args.horizon)
    print(json.dumps(build(args.inputs, args.output, configuration), indent=2))
