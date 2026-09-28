"""Capture-disjoint IoT-23 packet-window pilot using publisher per-flow labels.

Targets: any publisher-labelled malicious packet in a five-second window.
No-packet windows mean no observed malicious packet. Unmatched nonempty windows
without a known malicious packet have unknown targets and are excluded.
"""
from collections import defaultdict, Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

import numpy as np
from scapy.all import PcapReader, PcapWriter
from pipeline.build_dataset import FEATURES
from pipeline.feature_contract import PCAP_CONTRACT
from pipeline.pcap_replay import WindowAccumulator, summarize

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = {'tcp':6, 'udp':17, 'icmp':1, 'icmp6':58, 'ipv6-icmp':58}


def flow_key(src, sport, dst, dport, proto):
    if proto not in (6,17): sport = dport = 0
    return (*sorted(((src, int(sport)), (dst, int(dport)))), proto)


def read_labels(path, publisher_capture_label=None):
    flows = defaultdict(list)
    counts = Counter()
    fields = None
    with path.open() as file:
        for line in file:
            if line.startswith('#fields'):
                fields = line.split()[1:]
                if 'label' not in fields and publisher_capture_label != 'benign':
                    raise ValueError('Missing publisher labels; explicit documented benign capture annotation required')
                continue
            if line.startswith('#') or not line.strip(): continue
            if fields is None: raise ValueError('Missing Zeek fields header')
            values = line.split()
            if len(values) != len(fields): raise ValueError('Malformed Zeek labelled row')
            row = dict(zip(fields, values))
            proto = PROTOCOLS.get(row['proto'])
            label = row.get('label', publisher_capture_label or '').lower()
            counts[label] += 1
            if proto is None: continue
            binary = {'benign':0, 'malicious':1}.get(label, -1)
            start = float(row['ts']); duration = float(row['duration']) if row['duration'] != '-' else 0.0
            if not math.isfinite(start) or not math.isfinite(duration) or duration < 0: raise ValueError('Invalid labelled flow timestamps')
            key = flow_key(row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],proto)
            flows[key].append((start, start + duration, binary))
    for intervals in flows.values(): intervals.sort()
    return flows, dict(counts)


def packet_label(packet, flows):
    key = flow_key(packet.src,packet.src_port,packet.dst,packet.dst_port,packet.protocol)
    labels = {label for start,end,label in flows.get(key,()) if start-1e-6 <= packet.timestamp <= end+1e-6}
    return next(iter(labels)) if len(labels) == 1 else -1


def extract(entry, limit_seconds):
    source = ROOT / 'data/raw/iot23' / entry['id']
    pcap = source / entry['pcap']; log = source / entry['labels']
    flows, flow_counts = read_labels(log, entry.get("publisher_capture_label"))
    windows = {}; packet_labels = defaultdict(Counter)
    observed = Counter(); origin = None; previous = -math.inf; last = None
    derived = ROOT / 'data/pcap-corpus/iot23' / f"{entry['id']}.pcap"
    derived.parent.mkdir(parents=True,exist_ok=True)
    with PcapReader(str(pcap)) as reader, PcapWriter(str(derived), sync=True) as writer:
        for raw in reader:
            packet = summarize(raw)
            if packet is None: continue
            if not math.isfinite(packet.timestamp) or packet.timestamp < previous:
                raise ValueError('Capture must have finite chronological timestamps')
            previous = packet.timestamp
            if origin is None: origin = packet.timestamp
            if packet.timestamp >= origin + limit_seconds: break
            index = int((packet.timestamp-origin)//5)
            accumulator = windows.setdefault(index, WindowAccumulator(origin+index*5))
            if accumulator.packet_count >= 100000: raise ValueError('Replay packet cap exceeded')
            accumulator.add(packet)
            label = packet_label(packet, flows)
            packet_labels[index][label] += 1
            observed[label] += 1
            last = index
            writer.write(raw)
    if origin is None or last is None: raise ValueError('No supported packets')
    states = []; targets = []
    for index in range(last+1):
        states.append(windows.get(index,WindowAccumulator(origin+index*5)).as_state())
        counts = packet_labels[index]
        targets.append(1 if counts[1] else -1 if counts[-1] else 0)
    matrix = np.array([[s[f] for f in FEATURES] for s in states],dtype=np.float32)
    truth = np.array(targets,dtype=np.int64)
    # The final window is incomplete at capture/crop end and cannot be a target.
    starts = [i for i in range(len(states)-15) if (truth[i+11:i+15] >= 0).all()]
    if not starts: raise ValueError(f"No fully labelled targets for {entry['id']}")
    arrays = {
        'x': np.stack([matrix[i:i+12] for i in starts]),
        'y_state': np.stack([matrix[i+12:i+15] for i in starts]),
        'y_attack': np.stack([truth[i+12:i+15] for i in starts]).astype(np.float32),
        'y_stage': np.stack([truth[i+12:i+15] for i in starts]),
        'anchor_attack': np.array([truth[i+11] for i in starts], dtype=np.float32),
        'anchor_stage': np.array([truth[i+11] for i in starts]),
        'anchor_time': np.array([datetime.fromtimestamp(origin+(i+11)*5, timezone.utc).isoformat() for i in starts],dtype='U40'),
        'capture_id': np.array([entry['id']]*len(starts)),
        'anchor_packets': np.array([windows.get(i+11,WindowAccumulator(0)).packet_count for i in starts]),
    }
    fingerprint = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    metadata = {'id':entry['id'], 'partition':entry['partition'], 'source_pcap_sha256':fingerprint(pcap),
                'source_labels_sha256':fingerprint(log), 'derived_pcap':str(derived.relative_to(ROOT)), 'derived_pcap_sha256':fingerprint(derived),
                'label_basis':entry.get('label_basis','Publisher per-flow labels'), 'flow_label_counts':flow_counts, 'packet_label_counts':dict(observed),
                'windows':len(states), 'unknown_windows':int((truth<0).sum()), 'attack_windows':int((truth==1).sum()),
                'empty_windows':len(states)-len(windows), 'sequences':len(starts),
                'positive_targets':int(arrays['y_attack'][:,0].sum()), 'capture_start':origin}
    # This mapping is evaluation-only and is never included among input features.
    (derived.with_suffix('.window-labels.json')).write_text(json.dumps({'capture_sha256':fingerprint(derived),'window_seconds':5,'labels':targets,'provenance':'Publisher flow labels matched to individual packets; -1 denotes unknown'},indent=2)+'\n')
    return arrays, metadata


def build():
    plan = json.loads((ROOT/'datasets/iot23_pilot_sources.json').read_text())
    out = ROOT/'data/processed-iot23-pilot'; out.mkdir(parents=True,exist_ok=True)
    partitions = defaultdict(list); captures = []; hashes = set()
    for entry in plan['captures']:
        arrays, metadata = extract(entry,plan['maximum_capture_seconds'])
        if metadata['source_pcap_sha256'] in hashes: raise ValueError('Duplicate source capture across partitions')
        hashes.add(metadata['source_pcap_sha256'])
        partitions[entry['partition']].append(arrays); captures.append(metadata)
        print(json.dumps(metadata),flush=True)
    split_sizes = {}
    for name in ('train','validation','test'):
        batches = partitions[name]
        merged = {key:np.concatenate([b[key] for b in batches]) for key in batches[0]}
        if name != 'test' and np.unique(merged['y_attack'][:,0]).size < 2: raise ValueError(f'{name} lacks both target classes')
        np.savez_compressed(out/f'{name}.npz',**merged)
        split_sizes[name] = len(merged['x'])
    manifest = {'dataset':plan['dataset'], 'feature_contract':PCAP_CONTRACT, 'features':FEATURES,
                'feature_observed':{f:f not in ('failed_auth_count','identity_reuse_count') for f in FEATURES},
                'config':{'window_seconds':5,'sequence_length':12,'horizon':3},
                'stage_order':{'Normal':0,'Malicious traffic':1}, 'split_sizes':split_sizes,
                'captures':captures, 'selection_policy':plan['selection_policy'],
                'target_definition':__doc__, 'limitations':['Publisher labels not independently verified; v2 is work in progress.',
                    'Small IoT subset does not establish enterprise or attack-family generalization.',
                    'Binary malicious-traffic targets are not MITRE stages or proof of compromise.',
                    'Empty windows are valid no-observed-malicious-packet targets and may inflate aggregate metrics; report activity-stratified results.',
                    'Unknown packets remain features, but unknown target/anchor windows are excluded.']}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest

if __name__ == '__main__': build()
