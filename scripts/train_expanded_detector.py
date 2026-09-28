"""Fixed expanded-data experiment: choose on validation, then evaluate fresh captures."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from pipeline.current_detector import current_windows, merge, choose_threshold, evaluate
from pipeline.build_iot23_dataset import extract
from pipeline.build_dataset import FEATURES
from pipeline.train_baseline import fit_or_dummy
from pipeline.calibration import fit_ood_profile, ood_scores
from pipeline.feature_contract import PCAP_CONTRACT

ROOT=Path(__file__).resolve().parents[1]


def screening(result, gates):
    raw=result['groups']['all']; failures=[]
    if raw['tp']+raw['fn'] < gates['minimum_positive_test_windows']: failures.append('Insufficient positive test windows')
    if raw['tn']+raw['fp'] < gates['minimum_negative_test_windows']: failures.append('Insufficient negative test windows')
    if raw['recall'] is None or raw['recall'] < gates['minimum_raw_recall']: failures.append('Raw recall below gate')
    coverage=result['accepted_detection_fraction_all_positives']
    if coverage is None or coverage < gates['minimum_accepted_detection_fraction']: failures.append('Accepted detections across all positives below gate')
    if result['ood_rejection_rate'] > gates['maximum_rejection_rate']: failures.append('Rejection rate above gate')
    for name, group in result['groups'].items():
        if group['false_positive_rate'] is not None and group['false_positive_rate'] > gates['maximum_per_capture_fpr']:
            failures.append(f'False-positive budget exceeded: {name}')
    return {'passed':not failures,'failures':failures,'operational_approval':False}


def probability(model,x):
    return np.asarray(model.predict_proba(x)[:,list(model.classes_).index(1)],dtype=np.float64)


def validate_partitions(plan, inspected_ids):
    ids=[c['id'] for c in plan['captures']]
    if len(set(ids))!=len(ids): raise ValueError('Repeated capture ID')
    for c in plan['captures']:
        if c['partition']=='fresh_test' and c['id'] in inspected_ids:
            raise ValueError('Fresh test includes an inspected capture')
        if c['partition']=='train' and c['id'] in {'CTU-Honeypot-Capture-7-2','CTU-IoT-Malware-Capture-42-1','CTU-IoT-Malware-Capture-3-1'}:
            raise ValueError('Inspected test capture cannot enter training in this experiment')


def prepared_capture(entry, limit):
    cache=ROOT/'data/pcap-corpus/iot23'/f"{entry['id']}.extraction.json"
    code=hashlib.sha256((ROOT/'pipeline/build_iot23_dataset.py').read_bytes()+(ROOT/'pipeline/pcap_replay.py').read_bytes()).hexdigest()
    if cache.exists():
        record=json.loads(cache.read_text()); metadata=record.get('metadata',{})
        source=ROOT/'data/raw/iot23'/entry['id']
        if record.get('maximum_capture_seconds')==limit and record.get('extractor_sha256')==code:
            checks=[(source/entry['pcap'], metadata['source_pcap_sha256']),
                    (source/entry['labels'], metadata['source_labels_sha256']),
                    (ROOT/metadata['derived_pcap'],metadata['derived_pcap_sha256']),
                    ((ROOT/metadata['derived_pcap']).with_suffix('.window-labels.json'),record['window_labels_sha256'])]
            if all(hashlib.sha256(path.read_bytes()).hexdigest()==digest for path,digest in checks):
                return metadata
    _,metadata=extract(entry,limit)
    cache.write_text(json.dumps({'metadata':metadata,'maximum_capture_seconds':limit,'extractor_sha256':code,
        'window_labels_sha256':hashlib.sha256((ROOT/metadata['derived_pcap']).with_suffix('.window-labels.json').read_bytes()).hexdigest()},indent=2)+'\n')
    return metadata


def main():
    plan_path=ROOT/'datasets/iot23_expanded_v2.json';plan=json.loads(plan_path.read_text())
    provenance=[];parts={};seen=set()
    existing=json.loads((ROOT/'data/processed-iot23-pilot/manifest.json').read_text())
    old={c['id']:c for c in existing['captures']}
    validate_partitions(plan,set(old)|{'CTU-IoT-Malware-Capture-3-1'})
    inspected_hashes={c['source_pcap_sha256'] for c in existing['captures']}
    supplementary=json.loads((ROOT/'docs/release-evidence/iot23-supplementary-test.json').read_text())
    inspected_hashes.update(c['provenance']['source_pcap_sha256'] for c in supplementary['captures'])
    for entry in plan['captures']:
        raw=ROOT/'data/raw/iot23'/entry['id']/entry['pcap']
        digest=hashlib.sha256(raw.read_bytes()).hexdigest()
        if digest in seen: raise ValueError('Duplicate capture in expanded split')
        if entry['partition']=='fresh_test' and digest in inspected_hashes:
            raise ValueError('Fresh capture duplicates inspected capture bytes')
        seen.add(digest)
        if entry['id'] in old:
            metadata=old[entry['id']]
            if digest!=metadata['source_pcap_sha256']: raise ValueError('Existing source changed')
        else:
            metadata=prepared_capture(entry,plan['maximum_capture_seconds'])
        provenance.append(metadata)
        parts.setdefault(entry['partition'],[]).append(current_windows(entry['id']))
        print('Prepared',entry['id'],flush=True)
    splits={name:merge(batches) for name,batches in parts.items()}
    train=splits['train'];val=splits['validation']
    tx=np.log1p(train['x']);vx=np.log1p(val['x'])
    if np.unique(train['y']).size!=2 or np.unique(val['y']).size!=2: raise ValueError('Training and validation require both classes')
    cfg=plan['model_plan']['random_forest']
    models={'logistic':fit_or_dummy(tx,train['y'],cfg['seed']),
        'random_forest':RandomForestClassifier(n_estimators=cfg['n_estimators'],max_depth=cfg['max_depth'],min_samples_leaf=cfg['min_samples_leaf'],class_weight='balanced_subsample',random_state=cfg['seed'],n_jobs=2).fit(tx,train['y'])}
    ood=fit_ood_profile(tx[:,None,:],vx[:,None,:])
    folder=ROOT/'models/iot23-expanded-detector-v2';folder.mkdir(exist_ok=True)
    report={'plan_sha256':hashlib.sha256(plan_path.read_bytes()).hexdigest(),'capture_provenance':provenance,'models':{},'operational_claims_allowed':False,
            'implementation_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('scripts/train_expanded_detector.py','pipeline/current_detector.py','pipeline/build_iot23_dataset.py','pipeline/pcap_replay.py')},
            'split_sizes':{name:len(data['y']) for name,data in splits.items()}}
    ranked=[]
    for name,model in models.items():
        vp=probability(model,vx)
        score,threshold=choose_threshold(val,vp,plan['model_plan']['validation_fpr_budget_per_capture'])
        ranked.append((score,name))
        accepted=ood_scores(vx[:,None,:],ood['lower'],ood['upper'])<=ood['threshold']
        dest=folder/f'{name}.joblib'
        joblib.dump({'model':model,'threshold':threshold,'features':FEATURES,'input_transform':'log1p_nonnegative','ood':ood,'feature_contract':PCAP_CONTRACT,'task':'current_window_detection','plan_sha256':report['plan_sha256'],'operational_claims_allowed':False},dest)
        report['models'][name]={'validation_selection_f1':score,'threshold':threshold,'artifact_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'validation':evaluate(val,vp,threshold,accepted)}
    selected=max(ranked)[1];report['selected_by_validation']=selected
    # Selection and model hashes are persisted before making any test predictions.
    (folder/'frozen-selection.json').write_text(json.dumps(report,indent=2)+'\n')
    artifact=folder/f'{selected}.joblib';bundle=joblib.load(artifact)
    data=splits['fresh_test'];x=np.log1p(data['x'])
    accepted=ood_scores(x[:,None,:],ood['lower'],ood['upper'])<=ood['threshold']
    result=evaluate(data,probability(bundle['model'],x),bundle['threshold'],accepted)
    if hashlib.sha256(artifact.read_bytes()).hexdigest()!=report['models'][selected]['artifact_sha256']: raise ValueError('Selected model changed during test')
    report['fresh_test']=result
    report['screening']=screening(result,plan['model_plan']['experimental_gates'])
    report['release_decision']='not_promoted'
    report['limitations']=['Only two fresh capture sessions; benign Somfy device shared across splits.', 'Publisher v2 labels not independently audited; unknown labels excluded.', 'Current-window detection is not attack forecasting; overlapping windows are not independent trials.', 'Passing research screening alone does not establish production readiness.']
    dest=ROOT/'docs/release-evidence/expanded-detector-v2.json';dest.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'selected':selected,'fresh_test':result,'screening':report['screening']},indent=2))

if __name__=='__main__':main()
