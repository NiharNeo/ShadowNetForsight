from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "datasets" / "catalog.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def acquire(dataset_id: str, output_dir: Path) -> dict:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if dataset_id not in catalog:
        raise ValueError(f"Unknown dataset id {dataset_id!r}; choose from {sorted(catalog)}")
    entry = catalog[dataset_id]
    if not entry["url"].startswith("https://"):
        raise ValueError(f"{dataset_id} requires its documented external acquisition command.")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / entry["filename"]
    temporary = destination.with_suffix(destination.suffix + ".part")
    urllib.request.urlretrieve(entry["url"], temporary)
    temporary.replace(destination)
    manifest = {
        "dataset_id": dataset_id,
        "source_url": entry["url"],
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "path": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": sha256(destination),
        "citation": entry["citation"],
        "license_note": entry["license_note"],
    }
    (output_dir / "acquisition.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Acquire a catalogued public research dataset with provenance.")
    parser.add_argument("dataset_id")
    parser.add_argument("--output", type=Path, default=Path("data/raw"))
    args = parser.parse_args()
    print(json.dumps(acquire(args.dataset_id, args.output), indent=2))
