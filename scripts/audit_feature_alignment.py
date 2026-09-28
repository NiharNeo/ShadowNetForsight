"""Record extraction differences and sequence timing defects in existing artifacts."""
from pathlib import Path
import json
import numpy as np
from pipeline.train_baseline import load_split
from pipeline.feature_contract import CSV_CONTRACT, PCAP_CONTRACT

ROOT = Path(__file__).resolve().parents[1]

def main():
    directory = ROOT / 'data/processed-cic2018-multiday'
    timing = {}
    for name in ('train', 'validation', 'test'):
        split = load_split(directory, name)
        times = split['anchor_time'].astype('datetime64[s]').astype('int64')
        delta = np.diff(times)
        timing[name] = {'sequences': len(times), 'non_five_second_adjacent_anchors': int((delta != 5).sum()), 'largest_adjacent_gap_seconds': int(delta.max())}
    report = {
        'training_contract': CSV_CONTRACT, 'replay_contract': PCAP_CONTRACT,
        'equivalent': False,
        'differences': [
            {'feature': 'duration_mean', 'csv': 'Mean full flow durations as supplied by source CSV; no unit conversion', 'pcap': 'Mean duration in seconds of bidirectional flows restricted to the current packet window'},
            {'feature': 'iat_mean', 'csv': 'Mean of per-flow IAT means as supplied by source CSV', 'pcap': 'Mean gap in seconds between consecutive packets across all flows within the window'},
            {'feature': 'flow_count', 'csv': 'Flow records grouped by their start timestamp', 'pcap': 'Distinct bidirectional endpoint/protocol tuples observed in each packet window'},
            {'feature': 'bytes_sum', 'csv': 'Total supplied forward/backward flow bytes attributed to flow-start window', 'pcap': 'Captured packet lengths (including link-layer headers when present) within each window'},
            {'feature': 'unique_src_ips / unique_dst_ips', 'csv': 'Missing address columns become one unknown category', 'pcap': 'Actual packet addresses'},
            {'feature': 'time continuity', 'csv': 'Legacy sequence builder joined consecutive nonempty rows even across time gaps', 'pcap': 'Emits empty windows to preserve five-second timing'},
        ],
        'legacy_dataset_anchor_diagnostics': timing,
        'remediation': 'Train from independently labelled PCAP sessions via build_pcap_dataset, which shares WindowAccumulator with replay. Do not retrofit a contract tag or tune OOD bounds on demonstration captures.',
        'production_prediction_ready': False,
    }
    baseline = ROOT / 'data/models/product-baseline/metrics.json'
    if baseline.exists():
        report['rerun_static_baseline'] = json.loads(baseline.read_text())['splits']['test']['binary']
        report['baseline_scope'] = 'Original fixed CSV test split, not PCAP validation. No threshold or test-set tuning performed.'
    target = ROOT / 'docs/release-evidence/feature-alignment.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
