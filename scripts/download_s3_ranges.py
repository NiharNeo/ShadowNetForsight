from __future__ import annotations

import argparse
import concurrent.futures
import os
import random
import time
import urllib.request
from pathlib import Path


def fetch(url: str, part_path: Path, start: int, end: int, retries: int = 6) -> None:
    expected = end - start + 1
    if part_path.exists() and part_path.stat().st_size == expected:
        return
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
            temporary = part_path.with_suffix(".part.tmp")
            with urllib.request.urlopen(request, timeout=240) as response, temporary.open("wb") as stream:
                while chunk := response.read(1024 * 1024):
                    stream.write(chunk)
            os.replace(temporary, part_path)
            break
        except Exception:
            temporary = part_path.with_suffix(".part.tmp")
            temporary.unlink(missing_ok=True)
            if attempt == retries:
                raise
            time.sleep(min(30, (2**attempt) + random.random()))
    if part_path.stat().st_size != expected:
        raise IOError(f"Part {part_path.name} expected {expected} bytes, found {part_path.stat().st_size}")


def download(url: str, destination: Path, size: int, workers: int = 12, chunk_mib: int = 8) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    parts = destination.with_suffix(destination.suffix + ".parts")
    parts.mkdir(exist_ok=True)
    chunk_size = chunk_mib * 1024 * 1024
    ranges = [(start, min(start + chunk_size - 1, size - 1)) for start in range(0, size, chunk_size)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fetch, url, parts / f"{index:05d}.part", start, end) for index, (start, end) in enumerate(ranges)]
        for completed, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            future.result()
            print(f"completed {completed}/{len(futures)} parts", flush=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    with temporary.open("wb") as output:
        for index in range(len(ranges)):
            with (parts / f"{index:05d}.part").open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
    if temporary.stat().st_size != size:
        raise IOError(f"Final file expected {size} bytes, found {temporary.stat().st_size}")
    os.replace(temporary, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Resumably download a known-size public S3 object using ranged requests.")
    parser.add_argument("url")
    parser.add_argument("destination", type=Path)
    parser.add_argument("size", type=int)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--chunk-mib", type=int, default=8)
    args = parser.parse_args()
    download(args.url, args.destination, args.size, args.workers, args.chunk_mib)
