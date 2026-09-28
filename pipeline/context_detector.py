"""Joint packet-window and past connection features for a separate research model."""
from pathlib import Path
import hashlib
import json
import math
import numpy as np
from scapy.all import PcapReader
from pipeline.build_dataset import FEATURES
from pipeline.connection_context import ConnectionContext, CONTEXT_FEATURES
from pipeline.pcap_replay import WindowAccumulator, summarize

CONTRACT='shadownet.packet-context-window.v1'
CONTEXT_PARAMETERS={'seconds':60,'max_packets':500000}
CONTEXT_MODEL_FEATURES=FEATURES+list(CONTEXT_FEATURES)
ROOT=Path(__file__).resolve().parents[1]


def capture_windows(capture, directory=None):
    directory=directory or ROOT/'data/pcap-corpus/iot23'
    path=directory/f'{capture}.pcap';label_path=path.with_suffix('.window-labels.json')
    labels=json.loads(label_path.read_text())
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if digest!=labels['capture_sha256']:raise ValueError('Capture does not match labels')
    if labels.get('window_seconds')!=5:raise ValueError('Expected five-second labels')
    context=ConnectionContext(**CONTEXT_PARAMETERS);origin=None;index=0;window=None;rows=[];previous=-math.inf
    with PcapReader(str(path)) as reader:
        for raw in reader:
            p=summarize(raw)
            if p is None:continue
            if not math.isfinite(p.timestamp) or p.timestamp<previous:raise ValueError('Invalid chronological capture')
            previous=p.timestamp
            if origin is None:origin=p.timestamp;window=WindowAccumulator(origin)
            new_index=int((p.timestamp-origin)//5)
            if new_index>17280:raise ValueError('Capture exceeds 24 hours')
            while index<new_index:
                row=window.as_state();row.update(context.snapshot(origin+(index+1)*5));rows.append(row)
                index+=1;window=WindowAccumulator(origin+index*5)
            if window.packet_count>=100000:raise ValueError('Packet-window limit exceeded')
            window.add(p);context.add(p)
    if origin is None:raise ValueError('No supported packets')
    if len(rows)!=len(labels['labels'])-1:raise ValueError('Context and labelled windows are misaligned')
    selected=[i for i in range(len(rows)) if labels['labels'][i] in (0,1)]
    if not selected:raise ValueError('No labelled complete windows')
    return {'x':np.array([[rows[i][f] for f in CONTEXT_MODEL_FEATURES] for i in selected],dtype=np.float32),
            'y':np.array([labels['labels'][i] for i in selected],dtype=int),
            'capture_id':np.array([capture]*len(selected)), 'window_index':np.array(selected)}
