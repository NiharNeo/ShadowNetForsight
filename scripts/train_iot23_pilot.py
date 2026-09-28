"""Reproduce the fixed PCAP pilot; never automatically promote its checkpoint."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
import torch
from pipeline.train_lstm import train, TrainingConfig, load_split, tune_threshold
from pipeline.train_baseline import fit_or_dummy, positive_probability
from pipeline.evaluate import load_lstm, predict_lstm, early_warning
from pipeline.calibration import ood_scores
from pipeline.transforms import normalize_features

ROOT = Path(__file__).resolve().parents[1]


def counts(truth, predicted):
    truth = np.asarray(truth, dtype=bool); predicted = np.asarray(predicted, dtype=bool)
    tp = int((truth & predicted).sum()); fp = int((~truth & predicted).sum())
    fn = int((truth & ~predicted).sum()); tn = int((~truth & ~predicted).sum())
    return dict(support=len(truth), tp=tp, fp=fp, fn=fn, tn=tn,
                recall=tp/(tp+fn) if tp+fn else None,
                false_positive_rate=fp/(fp+tn) if fp+tn else None,
                precision=tp/(tp+fp) if tp+fp else None,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None)


def main():
    torch.set_num_threads(2)
    data = ROOT/'data/processed-iot23-pilot'; output = ROOT/'models/iot23-pilot-lstm'
    splits = {name:load_split(data,name) for name in ('train','validation','test')}
    configuration = TrainingConfig(epochs=30, patience=6, hidden_size=32, layers=1, batch_size=128)
    train(data,output,configuration)
    model, checkpoint = load_lstm(output/'lstm.pt')
    # Baseline uses the same log transform, capture partitions and validation FPR budget.
    baseline = fit_or_dummy(np.log1p(splits['train']['x'][:,-1,:]),splits['train']['y_attack'][:,0].astype(int),42)
    val_probability = positive_probability(baseline,np.log1p(splits['validation']['x'][:,-1,:]))
    thresholds,_ = tune_threshold({'y_attack':splits['validation']['y_attack'][:,:1]}, {'attack_probability':val_probability[:,None]})
    joblib.dump({'binary_model':baseline,'threshold':thresholds[0], 'input_transform':'log1p_nonnegative'},output/'baseline.joblib')
    report = {'dataset_manifest_sha256':hashlib.sha256((data/'manifest.json').read_bytes()).hexdigest(),
              'checkpoint_sha256':hashlib.sha256((output/'lstm.pt').read_bytes()).hexdigest(),
              'feature_contract':checkpoint['feature_contract'], 'baseline_threshold':thresholds[0],
              'selection':'One fixed training run; validation selects early stopping, temperature, OOD and thresholds; no test tuning.',
              'operational_claims_allowed':False, 'automatic_promotion':False, 'splits':{}}
    for name in ('validation','test'):
        split=splits[name]; probability=predict_lstm(model,checkpoint,split)['attack_probability']
        normalized=normalize_features(split['x'],checkpoint['normalization_mean'],checkpoint['normalization_scale'],checkpoint['input_transform'],checkpoint['normalization_clip'])
        accepted=ood_scores(normalized,checkpoint['ood_lower'],checkpoint['ood_upper']) <= checkpoint['ood_threshold']
        baseline_probability=positive_probability(baseline,np.log1p(split['x'][:,-1,:]))
        groups={'all':np.ones(len(accepted),dtype=bool),'active_anchor':split['anchor_packets']>0}
        groups.update({str(c):split['capture_id']==c for c in np.unique(split['capture_id'])})
        result={'ood_rejection_rate':float((~accepted).mean()), 'groups':{},
                'early_warning_raw':early_warning(split,probability,5,checkpoint['decision_threshold']),
                'early_warning_accepted':early_warning(split,np.where(accepted[:,None],probability,-1),5,checkpoint['decision_threshold'])}
        for group, mask in groups.items():
            horizon_results=[]
            for h in range(3):
                truth=split['y_attack'][:,h]; predicted=probability[:,h]>=checkpoint['decision_threshold'][h]
                horizon_results.append({'step':h+1,'raw':counts(truth[mask],predicted[mask]),
                    'accepted':counts(truth[mask & accepted],predicted[mask & accepted]),
                    'rejected_positive_targets':int(((truth>0)&mask&~accepted).sum()),
                    'rejected_negative_targets':int(((truth==0)&mask&~accepted).sum())})
            result['groups'][group]={'lstm':horizon_results,'baseline_next_window':counts(split['y_attack'][mask,0],baseline_probability[mask]>=thresholds[0])}
        report['splits'][name]=result
    report['promotion_blockers']=['Test capture has no labelled attacks after the 60-second warm-up, so held-out recall and early warning are unmeasured.', 'Small IoT pilot, not enterprise validation; publisher v2 is work in progress.']
    dest=ROOT/'docs/release-evidence/iot23-pilot-evaluation.json'; dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({n:{'ood':r['ood_rejection_rate'],**r['groups']['all']} for n,r in report['splits'].items()},indent=2))

if __name__=='__main__': main()
