"""Trace frozen detector errors to publisher-labelled flows; never rewrite labels."""
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import json
from scapy.all import PcapReader
from pipeline.build_iot23_dataset import flow_key, PROTOCOLS
from pipeline.pcap_replay import summarize

ROOT=Path(__file__).resolve().parents[1]


def read_details(path):
    flows=defaultdict(list);fields=None
    for line in path.open():
        if line.startswith('#fields'):fields=line.split()[1:];continue
        if line.startswith('#') or not line.strip():continue
        values=line.split()
        if fields is None or len(values)!=len(fields):raise ValueError('Malformed flow log')
        row=dict(zip(fields,values));proto=PROTOCOLS.get(row['proto'])
        if proto is None:continue
        start=float(row['ts']);duration=0 if row['duration']=='-' else float(row['duration'])
        key=flow_key(row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],proto)
        flows[key].append((start,start+duration,row))
    return flows


def matching_rows(packet,flows,tolerance=1e-6):
    key=flow_key(packet.src,packet.src_port,packet.dst,packet.dst_port,packet.protocol)
    return [row for start,end,row in flows.get(key,[]) if start-tolerance<=packet.timestamp<=end+tolerance]


def main():
    error_path=ROOT/'docs/release-evidence/expanded-detector-v2-errors.json'
    errors=json.loads(error_path.read_text());evaluation=json.loads((ROOT/'docs/release-evidence/expanded-detector-v2.json').read_text())
    ident='CTU-IoT-Malware-Capture-34-1'
    metadata=next(c for c in evaluation['capture_provenance'] if c['id']==ident)
    plan=json.loads((ROOT/'datasets/iot23_expanded_v2.json').read_text());entry=next(c for c in plan['captures'] if c['id']==ident)
    source=ROOT/'data/raw/iot23'/ident/entry['labels'];pcap=ROOT/metadata['derived_pcap']
    if hashlib.sha256(source.read_bytes()).hexdigest()!=metadata['source_labels_sha256'] or hashlib.sha256(pcap.read_bytes()).hexdigest()!=metadata['derived_pcap_sha256']:
        raise ValueError('Source evidence changed')
    flows=read_details(source);indices={e['window_index'] for e in errors['false_positive_windows']}
    audits={i:{'packets':0,'labels':Counter(),'services':Counter(),'destination_ports':Counter(),'tcp_flags':Counter(),'flow_ids':set(),'malicious_match_with_1ms_tolerance':0} for i in indices}
    with PcapReader(str(pcap)) as reader:
        for raw in reader:
            packet=summarize(raw)
            if packet is None:continue
            i=int((packet.timestamp-metadata['capture_start'])//5)
            if i not in indices:continue
            a=audits[i];a['packets']+=1
            rows=matching_rows(packet,flows)
            labels={row['label'].lower() for row in rows}
            a['labels'][next(iter(labels)) if len(labels)==1 else 'unknown_or_conflicting']+=1
            for row in rows:
                a['services'][row.get('service','-')]+=1;a['flow_ids'].add(row['uid'])
            a['destination_ports'][str(packet.dst_port)]+=1
            a['tcp_flags'][str(raw['TCP'].flags) if raw.haslayer('TCP') else 'not_tcp']+=1
            if any(r['label'].lower()=='malicious' for r in matching_rows(packet,flows,.001)):
                a['malicious_match_with_1ms_tolerance']+=1
    rows=[]
    for i,a in sorted(audits.items()):
        rows.append({'window_index':i,**{k:(dict(v) if isinstance(v,Counter) else sorted(v) if isinstance(v,set) else v) for k,v in a.items()}})
    result={'capture_id':ident,'artifact_sha256':errors['artifact_sha256'],'derived_pcap_sha256':metadata['derived_pcap_sha256'],
        'purpose':'Post-test error diagnosis; no labels, thresholds or model weights modified.',
        'tolerance_check':'1ms match is diagnostic only; training labels retain original 1us matching.',
        'windows':rows,'total_packets':sum(a['packets'] for a in rows),
        'malicious_matches_with_1ms_tolerance':sum(a['malicious_match_with_1ms_tolerance'] for a in rows)}
    dest=ROOT/'docs/release-evidence/expanded-detector-v2-flow-audit.json';dest.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
