"""Fixed diagnostic context experiment; inspected tests cannot qualify a release."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from pipeline.context_detector import capture_windows, CONTEXT_MODEL_FEATURES, CONTRACT, CONTEXT_PARAMETERS
from pipeline.current_detector import merge, choose_threshold, evaluate
from pipeline.calibration import fit_ood_profile, ood_scores

ROOT=Path(__file__).resolve().parents[1]


def main():
    plan_path=ROOT/'datasets/iot23_expanded_v2.json';plan=json.loads(plan_path.read_text())
    batches={};seen=set()
    for c in plan['captures']:
        raw=ROOT/'data/pcap-corpus/iot23'/f"{c['id']}.pcap"
        digest=hashlib.sha256(raw.read_bytes()).hexdigest()
        if digest in seen:raise ValueError('Duplicate capture across partitions')
        seen.add(digest)
        data=capture_windows(c['id']);batches.setdefault(c['partition'],[]).append(data)
        print('Extracted',c['id'],len(data['y']),flush=True)
    splits={n:merge(parts) for n,parts in batches.items()};train=splits['train'];val=splits['validation']
    tx=np.log1p(train['x']);vx=np.log1p(val['x'])
    cfg=plan['model_plan']['random_forest']
    model=RandomForestClassifier(n_estimators=cfg['n_estimators'],max_depth=cfg['max_depth'],min_samples_leaf=cfg['min_samples_leaf'],class_weight='balanced_subsample',random_state=cfg['seed'],n_jobs=2).fit(tx,train['y'])
    predict=lambda x:model.predict_proba(x)[:,list(model.classes_).index(1)]
    score,threshold=choose_threshold(val,predict(vx),.05);ood=fit_ood_profile(tx[:,None,:],vx[:,None,:])
    folder=ROOT/'models/iot23-context-detector';folder.mkdir(exist_ok=True);dest=folder/'random_forest.joblib'
    joblib.dump({'model':model,'threshold':threshold,'features':CONTEXT_MODEL_FEATURES,'feature_contract':CONTRACT,'context_parameters':CONTEXT_PARAMETERS,'ood':ood,'input_transform':'log1p_nonnegative','task':'current_window_detection','operational_claims_allowed':False},dest)
    report={'experiment':'Same expanded-data split and RF settings; add nine causal context features. Threshold and OOD use validation only.',
        'test_status':'Previously inspected; diagnostic only. Fresh independent tests still required.',
        'pre_fit_adjustment':'Initial extraction stopped at the 100000-packet context bound on the benign Echo capture. Before fitting, increased the explicit bound to 500000; no packets were silently dropped.',
        'plan_sha256':hashlib.sha256(plan_path.read_bytes()).hexdigest(),'artifact_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),
        'feature_contract':CONTRACT,'context_parameters':CONTEXT_PARAMETERS,'features':CONTEXT_MODEL_FEATURES,'threshold':threshold,'validation_selection_f1':score,
        'operational_claims_allowed':False,'release_decision':'not_promoted','splits':{}}
    for n in ('validation','fresh_test'):
        data=splits[n];x=np.log1p(data['x']);accepted=ood_scores(x[:,None,:],ood['lower'],ood['upper'])<=ood['threshold']
        report['splits']['inspected_test' if n=='fresh_test' else n]=evaluate(data,predict(x),threshold,accepted)
    errors=json.loads((ROOT/'docs/release-evidence/expanded-detector-v2-errors.json').read_text())
    test=splits['fresh_test'];collisions=[]
    for error in errors['false_positive_windows']:
        mask=(test['capture_id']=='CTU-IoT-Malware-Capture-34-1')&(test['window_index']==error['window_index'])
        vector=test['x'][mask][0]
        matches=(train['x']==vector).all(axis=1)&(train['y']==1)
        collisions.append({'window_index':error['window_index'],'malicious_training_collisions_with_context':int(matches.sum())})
    report['known_error_collisions']=collisions
    (ROOT/'docs/release-evidence/context-detector.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['splits']['inspected_test'],indent=2))

if __name__=='__main__':main()
