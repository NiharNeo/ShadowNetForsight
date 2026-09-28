"""Reproduce capture compatibility checks without fitting or changing the model."""
from pathlib import Path
from collections import Counter
import hashlib
import json
from backend.inference_service import LSTMInferenceService, ReplayInferenceSession
from pipeline.pcap_replay import StreamingPcapReplay
from pipeline.evaluate_capture import evaluate

ROOT = Path(__file__).resolve().parents[1]

def main():
    service = LSTMInferenceService(ROOT / 'models/cic2018-phase1-lstm/lstm.pt')
    if not service.available or service.error:
        raise RuntimeError(service.error or 'Checkpoint unavailable')
    results = []
    target_dir = ROOT / 'output/demo-recording-kit'
    target_dir.mkdir(parents=True, exist_ok=True)
    labels = json.loads((ROOT / 'data/demo/captures/pilot-manifest.json').read_text())
    for name in ['pilot-benign-3m.pcap', 'pilot-attack-3m.pcap']:
        path = ROOT / 'data/demo/captures' / name
        replay = StreamingPcapReplay(path, 5)
        inference = ReplayInferenceSession(service)
        statuses = Counter()
        points = []
        updates = []
        try:
            for _ in range(60):
                update = replay.advance(5)
                output = inference.ingest(update['states'])
                updates.append({**update, 'inference': output})
                if output['model_ready']:
                    statuses[output['uncertainty']['status']] += 1
                    points.append({'elapsed_seconds': update['elapsed_seconds'], 'uncertainty': output['uncertainty'], 'forecast': output['forecast']})
                if update['complete']:
                    break
            assert update['complete'], 'Capture did not finish within bounded replay'
            exported = {'schema_version': 1, 'capture': {'filename': name, 'capture_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'checkpoint_sha256': service.checkpoint_sha256}, 'updates': updates, 'complete': True, 'omitted_older_updates': 0, 'status': 'complete'}
            (target_dir / f'{path.stem}-analysis.json').write_text(json.dumps(exported, indent=2, allow_nan=False) + '\n')
            (target_dir / f'{path.stem}-evaluation.json').write_text(json.dumps(evaluate(exported, labels), indent=2, allow_nan=False) + '\n')
            results.append({'file': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'provenance': 'synthetic pipeline fixture; not independent detector validation', 'processed_packets': update['processed_packets'], 'complete': update['complete'], 'model_ready_updates': sum(statuses.values()), 'distribution_counts': dict(statuses), 'operational_alerting_enabled': output.get('operational_alerting_enabled'), 'outputs': points})
        finally:
            replay.close()
    report = {'checkpoint_sha256': service.checkpoint_sha256, 'scope': 'Every 5-second replay update of two synthetic 180-second PCAP fixtures. OOD rate is capture-specific, not benchmark accuracy.', 'captures': results}
    target = ROOT / 'output/demo-recording-kit/capture-compatibility.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps([{k:v for k,v in item.items() if k != 'outputs'} for item in results], indent=2))

if __name__ == '__main__':
    main()
