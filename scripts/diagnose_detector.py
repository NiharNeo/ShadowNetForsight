"""Reproduce packet-label tracing, exact collisions and causal error context."""
from pathlib import Path
import hashlib
import json
import numpy as np
from scripts.audit_detector_errors import main as audit_flows
from pipeline.build_dataset import FEATURES
from pipeline.connection_context import context_states, CONTEXT_CONTRACT

ROOT=Path(__file__).resolve().parents[1]


def main():
    audit_flows()
    out=ROOT/'docs/release-evidence'
    errors=json.loads((out/'expanded-detector-v2-errors.json').read_text())
    train=ROOT/'data/processed-iot23-pilot/train.npz';rows=[]
    with np.load(train,allow_pickle=False) as data:
        for error in errors['false_positive_windows']:
            vector=np.array([error['features'][f] for f in FEATURES],dtype=np.float32)
            match=(data['x'][:,-1,:]==vector).all(axis=1)
            rows.append({'false_positive_window_index':error['window_index'],'identical_training_windows':int(match.sum()),
                'malicious_training_windows':int((data['anchor_attack'][match]>0).sum()),
                'benign_training_windows':int((data['anchor_attack'][match]==0).sum()),
                'matching_capture_ids':sorted(set(data['capture_id'][match].tolist()))})
    report={'training_npz_sha256':hashlib.sha256(train.read_bytes()).hexdigest(),
        'comparison':'Exact float32 equality of all 31 current-window features against original pilot training anchors; no approximate matching.',
        'false_positive_windows_with_malicious_training_collision':sum(r['malicious_training_windows']>0 for r in rows),'windows':rows,
        'interpretation':'Under these publisher labels, current-window feature collisions cannot be distinguished by a deterministic classifier of this vector alone.'}
    (out/'current-window-feature-collisions.json').write_text(json.dumps(report,indent=2)+'\n')
    states=context_states(ROOT/'data/pcap-corpus/iot23/CTU-IoT-Malware-Capture-34-1.pcap')
    context={'contract':CONTEXT_CONTRACT,'purpose':'Causal context extraction on inspected errors; not model predictions or validation.',
        'false_positive_windows':[{'window_index':e['window_index'],'context':states[e['window_index']]} for e in errors['false_positive_windows']]}
    (out/'error-connection-context.json').write_text(json.dumps(context,indent=2)+'\n')

if __name__=='__main__':main()
