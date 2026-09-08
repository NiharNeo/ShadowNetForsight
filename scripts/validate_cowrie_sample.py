from __future__ import annotations

import json
from pathlib import Path

from pipeline.telemetry import StreamingTelemetry, adapt_message


def validate(path: Path) -> dict:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    events = [adapt_message(record, "auto") for record in records]
    stream = StreamingTelemetry(window_seconds=5, allowed_lateness=2)
    result = stream.ingest(events, flush=True)
    unknown_addresses = sum(event.src_ip == "unknown" or event.dst_ip == "unknown" for event in events)
    return {
        "records": len(records),
        "adapted_events": len(events),
        "emitted_states": len(result["states"]),
        "unknown_address_events": unknown_addresses,
        "sources": sorted({event.source for event in events}),
        "first_timestamp": min(event.timestamp for event in events),
        "last_timestamp": max(event.timestamp for event in events),
    }


if __name__ == "__main__":
    report = validate(Path("data/raw/cowrie-srds2025-sample.jsonl"))
    Path("data/evaluation").mkdir(parents=True, exist_ok=True)
    Path("data/evaluation/cowrie-srds2025-ingestion.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
