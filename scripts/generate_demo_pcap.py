from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap


def generate(output: Path, packets: int = 180) -> None:
    capture = []
    for index in range(packets):
        elapsed = index * 0.5
        if elapsed < 15:
            port, flags = 443, "PA"
        elif elapsed < 30:
            port, flags = 20 + index % 45, "S"
        else:
            port, flags = 22, "S"
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="185.220.101.4", dst="10.0.0.5")
            / TCP(sport=40000 + index % 4, dport=port, flags=flags)
        )
        packet.time = 1_700_000_000 + elapsed
        capture.append(packet)
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), capture)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/demo/demo_attack.pcap"))
    args = parser.parse_args()
    generate(args.output)
