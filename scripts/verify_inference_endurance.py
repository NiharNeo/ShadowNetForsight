"""Synthetic concurrent model exercise; not an accuracy or deployment capacity test."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.inference_service import LSTMInferenceService


def verify(duration: float, workers: int) -> dict:
    service = LSTMInferenceService(ROOT / 'models/cic2018-phase1-lstm/lstm.pt')
    if not service.available:
        raise RuntimeError(service.error)
    states = [dict.fromkeys(service.features, 0.0) for _ in range(service.sequence_length)]
    started = time.monotonic()
    deadline = started + duration
    def exercise(_):
        timings = []
        while time.monotonic() < deadline:
            before = time.monotonic()
            result = service.predict(states)
            assert len(result['forecast']) == service.model.horizon
            assert not result['operational_alerting_enabled']
            assert all(not point['alert'] for point in result['forecast'])
            json.dumps(result, allow_nan=False)
            timings.append((time.monotonic() - before) * 1000)
        return timings
    with ThreadPoolExecutor(max_workers=workers) as pool:
        timings = sorted(value for batch in pool.map(exercise, range(workers)) for value in batch)
    if not timings:
        raise RuntimeError('No predictions completed')
    return dict(scope='synthetic in-process inference including explanations; not HTTP, real traffic, accuracy or capacity certification',
                duration_seconds=round(time.monotonic()-started, 2), workers=workers, predictions=len(timings),
                p95_ms=round(timings[min(len(timings)-1, int(len(timings)*0.95))], 2),
                max_ms=round(max(timings), 2), checkpoint_sha256=service.checkpoint_sha256,
                finite_outputs=True, operational_alerts=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=float, default=30)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600 or not 1 <= args.workers <= 32:
        parser.error('Use 1–3600 seconds and 1–32 workers')
    report = verify(args.seconds, args.workers)
    output = ROOT / 'data/workflow/inference-endurance.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
