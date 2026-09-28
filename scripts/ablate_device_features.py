"""Diagnostic ablation after inspecting v2 errors; never independent release evidence."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from pipeline.current_detector import current_windows, merge, choose_threshold, evaluate
from pipeline.build_dataset import FEATURES
from pipeline.calibration import fit_ood_profile, ood_scores

ROOT=Path(__file__).resolve().parents[1]
EXCLUDED=('ttl_mean','ttl_variance','tcp_window_mean')


def selected_features():
    names=[f for f in FEATURES if f not in EXCLUDED]
    return names, np.array([FEATURES.index(f) for f in names])


def main():
    plan=json.loads((ROOT/'datasets/iot23_expanded_v2.json').read_text())
    original=json.loads((ROOT/'docs/release-evidence/expanded-detector-v2.json').read_text())
    names,indices=selected_features()
    splits={n:merge([current_windows(c['id']) for c in plan['captures'] if c['partition']==n]) for n in ('train','validation','fresh_test')}
    tx=np.log1p(splits['train']['x'][:,indices]);vx=np.log1p(splits['validation']['x'][:,indices])
    cfg=plan['model_plan']['random_forest']
    model=RandomForestClassifier(n_estimators=cfg['n_estimators'],max_depth=cfg['max_depth'],min_samples_leaf=cfg['min_samples_leaf'],class_weight='balanced_subsample',random_state=cfg['seed'],n_jobs=2).fit(tx,splits['train']['y'])
    probability=lambda x:model.predict_proba(x)[:,list(model.classes_).index(1)]
    score,threshold=choose_threshold(splits['validation'],probability(vx),.05)
    profile=fit_ood_profile(tx[:,None,:],vx[:,None,:])
    folder=ROOT/'models/iot23-device-ablation';folder.mkdir(exist_ok=True)
    path=folder/'random_forest.joblib'
    joblib.dump({'model':model,'threshold':threshold,'features':names,'input_transform':'log1p_nonnegative','ood':profile,'task':'current_window_detection','operational_claims_allowed':False},path)
    report={'purpose':'Post-test diagnostic ablation; test already inspected. No deployment approval.',
            'excluded_features':list(EXCLUDED),'remaining_features':names,'artifact_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'validation_f1':score,'threshold':threshold,'operational_claims_allowed':False,'splits':{}}
    for n in ('validation','fresh_test'):
        d=splits[n];x=np.log1p(d['x'][:,indices])
        accepted=ood_scores(x[:,None,:],profile['lower'],profile['upper'])<=profile['threshold']
        report['splits']['inspected_test' if n=='fresh_test' else n]=evaluate(d,probability(x),threshold,accepted)
    report['frozen_v2_comparison']=original['fresh_test']
    dest=ROOT/'docs/release-evidence/device-feature-ablation.json';dest.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'validation':report['splits']['validation']['groups']['all'],'inspected_test':report['splits']['inspected_test'],'threshold':threshold},indent=2))

if __name__=='__main__':main()
