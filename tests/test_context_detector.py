from pathlib import Path
import tempfile
import unittest
import json
import hashlib
import numpy as np
from scapy.all import Ether,IP,TCP,wrpcap
from pipeline.context_detector import capture_windows,CONTEXT_MODEL_FEATURES
from pipeline.current_detector import current_windows
from pipeline.build_dataset import FEATURES

class ContextDetectorTests(unittest.TestCase):
    def test_joint_extraction_preserves_base_features_and_causal_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);path=folder/'capture.pcap';packets=[]
            for t,dst in [(100,'10.0.0.2'),(101,'10.0.0.2'),(105,'10.0.0.3'),(106,'10.0.0.3'),(110,'10.0.0.4'),(115,'10.0.0.5'),(120,'10.0.0.6')]:
                p=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='10.0.0.1',dst=dst)/TCP(sport=1000,dport=80,flags='S');p.time=t;packets.append(p)
            wrpcap(str(path),packets)
            path.with_suffix('.window-labels.json').write_text(json.dumps({'capture_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'window_seconds':5,'labels':[0,-1,1,0,1]}))
            data=capture_windows('capture',folder);old=current_windows('capture',folder)
            np.testing.assert_array_equal(data['x'][:,:len(FEATURES)],old['x'])
            self.assertEqual(data['window_index'].tolist(),[0,2,3])
            self.assertEqual(data['y'].tolist(),[0,1,0])
            destinations=CONTEXT_MODEL_FEATURES.index('context_destination_endpoints')
            self.assertEqual(data['x'][:,destinations].tolist(),[1,3,4])
            # Unknown-labelled history is observable traffic, not a leaked label.
            self.assertEqual(data['x'][1,CONTEXT_MODEL_FEATURES.index('context_packets')],5)
            self.assertEqual(capture_windows('capture',folder)['x'][0,destinations],1)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'does not match'):capture_windows('capture',folder)
