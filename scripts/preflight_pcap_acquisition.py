from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "datasets" / "cicids2018_raw_pcap_sources.json"


def preflight(plan_path: Path, destination: Path, capture_id: str | None = None) -> dict:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    captures = {capture["id"]: capture for capture in plan["captures"]}
    selected_id = capture_id or plan["recommended_first_capture"]
    if selected_id not in captures:
        raise ValueError(f"Unknown capture {selected_id!r}; choose from {sorted(captures)}")

    capture = captures[selected_id]
    archive_bytes = int(capture["archive_bytes"])
    required_bytes = int(archive_bytes * float(plan.get("minimum_working_space_factor", 2.0)))
    probe = destination if destination.exists() else destination.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free_bytes = shutil.disk_usage(probe).free
    source = plan["bucket"] + "/".join(capture["object"].split("/")[-2:])
    return {
        "ready": free_bytes >= required_bytes,
        "capture_id": selected_id,
        "source": source,
        "archive_bytes": archive_bytes,
        "minimum_working_bytes": required_bytes,
        "free_bytes": free_bytes,
        "shortfall_bytes": max(0, required_bytes - free_bytes),
        "destination": str(destination.resolve()),
        "next_command_when_ready": (
            f"aws s3 cp --no-sign-request --region {plan['region']} "
            f"'{source}' '{destination.resolve()}'"
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check disk capacity before acquiring an official raw PCAP archive.")
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--destination", type=Path, default=ROOT / "data" / "raw-pcap" / "pcap.zip")
    parser.add_argument("--capture")
    args = parser.parse_args()
    result = preflight(args.plan, args.destination, args.capture)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ready"] else 2)
