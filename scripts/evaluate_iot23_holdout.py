"""Evaluate supplementary captures without training, calibration or threshold changes."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
import torch
from pipeline.build_iot23_dataset import extract
from pipeline.evaluate import load_lstm, predict_lstm, early_warning
from pipeline.calibration import ood_scores
from pipeline.transforms import normalize_features
from pipeline.train_baseline import positive_probability
from scripts.train_iot23_pilot import counts

ROOT=Path(__file__).resolve().parents[1]


def verify_frozen(path, expected):
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f'Frozen artifact changed: {path.name}')
    return actual


def evaluate_split(split, model, checkpoint, baseline):
    probability=predict_lstm(model,checkpoint,split)['attack_probability']
    x=normalize_features(split['x'],checkpoint['normalization_mean'],checkpoint['normalization_scale'],checkpoint['input_transform'],checkpoint['normalization_clip'])
    accepted=ood_scores(x,checkpoint['ood_lower'],checkpoint['ood_upper']) <= checkpoint['ood_threshold']
    result={'sequences':len(accepted), 'ood_rejection_rate':float((~accepted).mean()),'horizons':[]}
    for h,threshold in enumerate(checkpoint['decision_threshold']):
        truth=split['y_attack'][:,h]; predicted=probability[:,h]>=threshold
        positive=int((truth>0).sum())
        result['horizons'].append({'step':h+1,'threshold':threshold,
            'raw':counts(truth,predicted), 'accepted':counts(truth[accepted],predicted[accepted]),
            'active_anchor':counts(truth[split['anchor_packets']>0],predicted[split['anchor_packets']>0]),
            'rejected_positive_targets':int(((truth>0)&~accepted).sum()),
            'rejected_negative_targets':int(((truth==0)&~accepted).sum()),
            'accepted_detection_fraction_all_positives':float(((truth>0)&predicted&accepted).sum()/positive) if positive else None})
    baseline_probability=positive_probability(baseline['binary_model'],np.log1p(split['x'][:,-1,:]))
    result['baseline_next_window']=counts(split['y_attack'][:,0],baseline_probability>=baseline['threshold'])
    result['early_warning_raw']=early_warning(split,probability,5,checkpoint['decision_threshold'])
    result['early_warning_accepted']=early_warning(split,np.where(accepted[:,None],probability,-1),5,checkpoint['decision_threshold'])
    return result


def main():
    torch.set_num_threads(2)
    plan_path=ROOT/'datasets/iot23_supplementary_test.json'; plan=json.loads(plan_path.read_text())
    folder=ROOT/'models/iot23-pilot-lstm'
    verify_frozen(folder/'lstm.pt',plan['checkpoint_sha256'])
    verify_frozen(folder/'baseline.joblib',plan['baseline_sha256'])
    model,checkpoint=load_lstm(folder/'lstm.pt'); baseline=joblib.load(folder/'baseline.joblib')
    original=json.loads((ROOT/'data/processed-iot23-pilot/manifest.json').read_text())
    used={c['source_pcap_sha256'] for c in original['captures']}
    report={'checkpoint_sha256':plan['checkpoint_sha256'],'baseline_sha256':plan['baseline_sha256'],
        'plan_sha256':hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        'selection_policy':plan['selection_policy'],'training_or_tuning_performed':False,
        'operational_claims_allowed':False,'captures':[]}
    for entry in plan['captures']:
        source=ROOT/'data/raw/iot23'/entry['id']/entry['pcap']
        if hashlib.sha256(source.read_bytes()).hexdigest() in used:
            raise ValueError('Supplementary capture duplicates an existing capture')
        used.add(hashlib.sha256(source.read_bytes()).hexdigest())
        split,metadata=extract(entry,plan['maximum_capture_seconds'])
        report['captures'].append({'provenance':metadata,'evaluation':evaluate_split(split,model,checkpoint,baseline)})
    verify_frozen(folder/'lstm.pt',plan['checkpoint_sha256'])
    verify_frozen(folder/'baseline.joblib',plan['baseline_sha256'])
    report['limitations']=['One additional capture does not establish network-wide generalization.',
        'Publisher labels are not independently audited; overlapping windows are correlated.',
        'Traffic-window onsets are not evidence of forecasting initial compromise.']
    dest=ROOT/'docs/release-evidence/iot23-supplementary-test.json'
    dest.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
