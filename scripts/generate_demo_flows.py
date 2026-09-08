from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd


def generate(output: Path, seconds: int = 180) -> None:
    start = datetime(2026, 1, 1, 10, 0, 0)
    rows = []
    benign_until = seconds * 0.40
    reconnaissance_until = seconds * 0.70
    for index in range(seconds * 2):
        elapsed = index / 2
        if elapsed < benign_until:
            label, dst_port, syn, ack = "Benign", 443, 1, 1
        elif elapsed < reconnaissance_until:
            label, dst_port, syn, ack = "Infiltration", 20 + (index % 45), 3, 1
        else:
            label, dst_port, syn, ack = "SSH-Bruteforce", 22, 5, 0
        rows.append({
            "Timestamp": start + timedelta(seconds=elapsed),
            "Src IP": f"185.220.101.{4 + index % 2}",
            "Dst IP": "10.0.0.5",
            "Dst Port": dst_port,
            "Protocol": 6,
            "Flow Duration": 1000 + index * 3,
            "Tot Fwd Pkts": 4 + index % 5,
            "Tot Bwd Pkts": 2 + index % 3,
            "TotLen Fwd Pkts": 600 + index,
            "TotLen Bwd Pkts": 220 + index,
            "Flow IAT Mean": 80 - min(elapsed / 3, 50),
            "SYN Flag Cnt": syn,
            "ACK Flag Cnt": ack,
            "RST Flag Cnt": int(elapsed > 100),
            "PSH Flag Cnt": int(elapsed > 120),
            "Label": label,
        })
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/demo/demo_flows.csv"))
    args = parser.parse_args()
    generate(args.output)
