"""Current-window detection experiment, separate from future-window forecasting."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from pipeline.build_dataset import FEATURES
from pipeline.pcap_calibration import pcap_states
from pipeline.train_baseline import fit_or_dummy, positive_probability
from pipeline.calibration import fit_ood_profile, ood_scores
from scripts.train_iot23_pilot import counts

ROOT = Path(__file__).resolve().parents[1]


def current_windows(capture, directory=None):
    directory=directory or ROOT/'data/pcap-corpus/iot23'
    path=directory/f'{capture}.pcap'
    labels=json.loads(path.with_suffix('.window-labels.json').read_text())
    if hashlib.sha256(path.read_bytes()).hexdigest()!=labels['capture_sha256']:
        raise ValueError('Capture does not match labels')
    states=pcap_states(path)
    if len(states)!=len(labels['labels']):
        raise ValueError('Window count differs from labels')
    # Never require future labels, future packets, or a minute of history to detect now.
    indices=[i for i,y in enumerate(labels['labels'][:-1]) if y in (0,1)]
    return {'x':np.array([[states[i][f] for f in FEATURES] for i in indices],dtype=np.float32),
            'y':np.array([labels['labels'][i] for i in indices],dtype=int),
            'capture_id':np.array([capture]*len(indices)),
            'window_index':np.array(indices)}


def merge(batches):
    return {key:np.concatenate([b[key] for b in batches]) for key in batches[0]}


def choose_threshold(data, probabilities, budget=.05):
    """Validation-only budget enforced on each capture, including active windows."""
    probabilities=np.asarray(probabilities,dtype=np.float64)
    active=data['x'][:,FEATURES.index('flow_count')]>0
    groups=[data['capture_id']==c for c in np.unique(data['capture_id'])]
    groups += [g & active for g in list(groups)]
    candidates=np.unique(np.append(np.quantile(probabilities,np.linspace(0,1,401)),np.nextafter(float(probabilities.max()),np.inf)))
    ranked=[]
    for threshold in candidates:
        pred=probabilities>=threshold
        if any(pred[g & (data['y']==0)].mean()>budget for g in groups if (g & (data['y']==0)).any()): continue
        score=counts(data['y'],pred)['f1'] or 0
        ranked.append((score,float(threshold)))
    return max(ranked)


def evaluate(data, probability, threshold, accepted):
    pred=np.asarray(probability,dtype=np.float64)>=threshold; y=data['y']; positives=int(y.sum())
    active=data['x'][:,FEATURES.index('flow_count')]>0
    groups={'all':np.ones(len(y),dtype=bool),'active_windows':active}
    groups.update({str(c):data['capture_id']==c for c in np.unique(data['capture_id'])})
    groups.update({str(c)+' / active':(data['capture_id']==c)&active for c in np.unique(data['capture_id'])})
    return {'groups':{name:counts(y[mask],pred[mask]) for name,mask in groups.items()},
            'ood_rejection_rate':float((~accepted).mean()),'accepted':counts(y[accepted],pred[accepted]),
            'rejected_positive_windows':int(((y==1)&~accepted).sum()),
            'rejected_negative_windows':int(((y==0)&~accepted).sum()),
            'accepted_detection_fraction_all_positives':float(((y==1)&pred&accepted).sum()/positives) if positives else None}


def run():
    manifest_path=ROOT/'data/processed-iot23-pilot/manifest.json'
    manifest=json.loads(manifest_path.read_text())
    splits={n:merge([current_windows(c['id']) for c in manifest['captures'] if c['partition']==n]) for n in ('train','validation','test')}
    # Previously inspected supplementary test is diagnostic, never training data.
    splits['inspected_supplementary']=current_windows('CTU-IoT-Malware-Capture-3-1')
    train=splits['train']; val=splits['validation']
    tx=np.log1p(train['x']); vx=np.log1p(val['x'])
    models={'logistic':fit_or_dummy(tx,train['y'],42),
            'random_forest':RandomForestClassifier(n_estimators=200,max_depth=10,min_samples_leaf=5,class_weight='balanced_subsample',random_state=42,n_jobs=2).fit(tx,train['y'])}
    ood=fit_ood_profile(tx[:,None,:],vx[:,None,:])
    report={'task':'Classify the just-completed five-second window, not forecast an attack.',
            'feature_contract':manifest['feature_contract'],'manifest_sha256':hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            'test_status':'Previously inspected captures; diagnostic comparison only, not fresh untouched validation.',
            'selection':'Two fixed models; select maximum validation F1 with <=5% FPR for every validation capture and its active-window subset. No test tuning.',
            'operational_claims_allowed':False,'models':{}}
    selection=[]
    folder=ROOT/'models/iot23-current-detector';folder.mkdir(exist_ok=True)
    for name,model in models.items():
        vp=model.predict_proba(vx)[:,list(model.classes_).index(1)] if name=='random_forest' else positive_probability(model,vx)
        score,threshold=choose_threshold(val,vp);selection.append((score,name))
        result={'validation_selection_f1':score,'threshold':threshold,'splits':{}}
        for split_name,data in splits.items():
            x=np.log1p(data['x'])
            prob=model.predict_proba(x)[:,list(model.classes_).index(1)] if name=='random_forest' else positive_probability(model,x)
            accepted=ood_scores(x[:,None,:],ood['lower'],ood['upper'])<=ood['threshold']
            result['splits'][split_name]=evaluate(data,prob,threshold,accepted)
        bundle={'model':model,'threshold':threshold,'features':FEATURES,'input_transform':'log1p_nonnegative','ood':ood,'feature_contract':manifest['feature_contract'],'task':'current_window_detection','operational_claims_allowed':False}
        dest=folder/f'{name}.joblib';joblib.dump(bundle,dest)
        result['artifact_sha256']=hashlib.sha256(dest.read_bytes()).hexdigest()
        report['models'][name]=result
    report['selected_by_validation']=max(selection)[1]
    report['release_decision']='not_promoted'
    report['promotion_blockers']=['No fresh untouched capture evaluation for this iteration.', 'Representative multi-network data and pre-agreed operational acceptance gates are still required.']
    dest=ROOT/'docs/release-evidence/current-detector.json';dest.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({name:{'threshold':r['threshold'],'splits':{n:s['groups']['all'] for n,s in r['splits'].items()}} for name,r in report['models'].items()},indent=2))

if __name__=='__main__':run()
