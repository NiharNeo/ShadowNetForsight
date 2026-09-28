from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from scapy.all import Ether, IP, UDP, wrpcap
from pipeline.build_iot23_dataset import flow_key, packet_label, read_labels, extract
from pipeline.pcap_calibration import pcap_states
from pipeline.build_dataset import FEATURES
import numpy as np


class IoT23DatasetTests(unittest.TestCase):
    def test_packet_labels_match_reverse_flow_and_time_but_not_future(self):
        flows = {flow_key('a',10,'b',20,6):[(100,105,1)]}
        packet = SimpleNamespace(src='b',src_port=20,dst='a',dst_port=10,protocol=6,timestamp=104)
        self.assertEqual(packet_label(packet,flows),1)
        packet.timestamp = 106
        self.assertEqual(packet_label(packet,flows),-1)
        packet.timestamp = 104
        flows[next(iter(flows))].append((100,105,0))
        self.assertEqual(packet_label(packet,flows),-1)

    def test_publisher_log_unknown_labels_are_not_benign(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'labels'
            path.write_text('#fields ts id.orig_h id.orig_p id.resp_h id.resp_p proto duration label\n100 a 1 b 2 udp - Background\n')
            flows, counts = read_labels(path)
            self.assertEqual(next(iter(flows.values()))[0][2],-1)
            self.assertEqual(counts,{'background':1})

    def test_extracted_features_equal_replay_and_labels_are_separate(self):
        with tempfile.TemporaryDirectory() as directory, patch('pipeline.build_iot23_dataset.ROOT',Path(directory)):
            source = Path(directory)/'data/raw/iot23/capture'; source.mkdir(parents=True)
            packets = []
            for i in range(100):
                p=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='10.0.0.1',dst='10.0.0.2')/UDP(sport=1000 if i<50 else 2000,dport=53)
                p.time=100+i; packets.append(p)
            wrpcap(str(source/'capture.pcap'),packets)
            (source/'labels').write_text('#fields ts id.orig_h id.orig_p id.resp_h id.resp_p proto duration label\n100 10.0.0.1 1000 10.0.0.2 53 udp 49 Benign\n150 10.0.0.1 2000 10.0.0.2 53 udp 49 Malicious\n')
            arrays, metadata=extract({'id':'capture','pcap':'capture.pcap','labels':'labels','partition':'train'},7200)
            states=pcap_states(Path(directory)/metadata['derived_pcap'])
            np.testing.assert_array_equal(arrays['x'][0], np.array([[s[f] for f in FEATURES] for s in states[:12]],dtype=np.float32))
            self.assertEqual(metadata['unknown_windows'],0)
            self.assertEqual(metadata['attack_windows'],10)
            self.assertNotIn('label',FEATURES)

    def test_missing_label_requires_explicit_publisher_annotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'labels'
            path.write_text('#fields ts id.orig_h id.orig_p id.resp_h id.resp_p proto duration\n100 a 1 b 2 udp 1\n')
            with self.assertRaisesRegex(ValueError, 'Missing publisher labels'):
                read_labels(path)
            flows, _=read_labels(path, 'benign')
            self.assertEqual(next(iter(flows.values()))[0][2],0)

    def test_early_warning_does_not_bridge_unknown_gaps_or_credit_issue_time(self):
        from pipeline.evaluate import early_warning
        split={'anchor_time':np.array(['2026-01-01T00:00:00','2026-01-01T00:00:10']),
               'y_attack':np.array([[0],[1]])}
        result=early_warning(split,np.ones((2,1)),5,.5)
        self.assertEqual(result['attack_onsets'],0)
        split['anchor_time'][1]='2026-01-01T00:00:05'
        result=early_warning(split,np.ones((2,1)),5,.5)
        self.assertEqual(result['attack_onsets'],1)
        self.assertEqual(result['onsets_forecast_early'],0)
