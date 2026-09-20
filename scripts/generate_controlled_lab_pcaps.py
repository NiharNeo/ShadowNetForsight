from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, Raw, wrpcap


BASE_TIMESTAMP = 1_780_000_000.0
CLIENT = "10.10.0.20"
WEB = "10.10.0.5"
DNS_SERVER = "10.10.0.53"
LAB_SOURCE = "192.0.2.44"
CLIENT_MAC = "02:00:00:00:10:20"
SERVER_MAC = "02:00:00:00:10:05"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _benign_packet(index: int, timestamp: float):
    mode = index % 5
    if mode == 0:
        packet = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=DNS_SERVER, ttl=64)
                  / UDP(sport=53000 + index % 200, dport=53)
                  / DNS(rd=1, qd=DNSQR(qname=f"service-{index % 12}.lab.local")))
    elif mode in (1, 2, 3):
        packet = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=WEB, ttl=64)
                  / TCP(sport=41000 + index % 500, dport=443, flags="PA", window=64240,
                        seq=1000 + index, ack=2000 + index)
                  / Raw(load=b"approved-lab-https"))
    else:
        packet = (Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=WEB, dst=CLIENT, ttl=63)
                  / TCP(sport=22, dport=42000 + index % 100, flags="A", window=50100,
                        seq=3000 + index, ack=4000 + index))
    packet.time = timestamp
    return packet


def generate(output_dir: Path, duration_seconds: int = 900) -> dict:
    if duration_seconds < 75:
        raise ValueError("duration_seconds must be at least 75 for the temporal model")
    output_dir.mkdir(parents=True, exist_ok=True)
    benign_path = output_dir / "pilot-benign-15m.pcap"
    attack_path = output_dir / "pilot-attack-15m.pcap"
    recon_start = duration_seconds // 3
    access_start = 2 * duration_seconds // 3

    benign = []
    attack = []
    for second in range(duration_seconds):
        timestamp = BASE_TIMESTAMP + second
        benign.append(_benign_packet(second, timestamp))
        if second < recon_start:
            attack.append(_benign_packet(second, timestamp))
        elif second < access_start:
            port = 20 + second % 80
            packet = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=LAB_SOURCE, dst=WEB, ttl=48)
                      / TCP(sport=45000 + second % 1000, dport=port, flags="S", window=1024,
                            seq=5000 + second))
            packet.time = timestamp
            attack.append(packet)
        else:
            packet = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=LAB_SOURCE, dst=WEB, ttl=48)
                      / TCP(sport=46000 + second % 500, dport=22, flags="S", window=1024,
                            seq=7000 + second))
            packet.time = timestamp
            attack.append(packet)

    wrpcap(str(benign_path), benign)
    wrpcap(str(attack_path), attack)
    generated_at = datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": 1,
        "dataset": "ShadowNet controlled-lab synthetic pilot",
        "status": "pilot_only_not_for_final_claims",
        "generated_at": generated_at,
        "generator": "scripts/generate_controlled_lab_pcaps.py",
        "safety": "Packets were written directly to PCAP files; no network traffic was transmitted.",
        "window_seconds": 5,
        "captures": [
            {
                "role": "benign_pilot",
                "path": benign_path.name,
                "sha256": _sha256(benign_path),
                "bytes": benign_path.stat().st_size,
                "packets": len(benign),
                "duration_seconds": duration_seconds,
                "timeline": [{"start_seconds": 0, "end_seconds": duration_seconds,
                              "label": 0, "stage": "Normal"}],
            },
            {
                "role": "attack_progression_pilot",
                "path": attack_path.name,
                "sha256": _sha256(attack_path),
                "bytes": attack_path.stat().st_size,
                "packets": len(attack),
                "duration_seconds": duration_seconds,
                "timeline": [
                    {"start_seconds": 0, "end_seconds": recon_start, "label": 0, "stage": "Normal"},
                    {"start_seconds": recon_start, "end_seconds": access_start, "label": 1, "stage": "Reconnaissance"},
                    {"start_seconds": access_start, "end_seconds": duration_seconds, "label": 1, "stage": "Initial Access"},
                ],
            },
        ],
        "limitations": [
            "Synthetic pilot traffic is not representative evidence for deployment.",
            "Authentication outcomes are unavailable in packet-only PCAP and require joined honeypot logs.",
            "Additional independent sessions are required for train, validation and untouched test partitions.",
        ],
    }
    (output_dir / "pilot-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate safe offline controlled-lab pilot PCAPs")
    parser.add_argument("--output", type=Path, default=Path("data/controlled-lab/pilot"))
    parser.add_argument("--duration-seconds", type=int, default=900)
    arguments = parser.parse_args()
    print(json.dumps(generate(arguments.output, arguments.duration_seconds), indent=2))
