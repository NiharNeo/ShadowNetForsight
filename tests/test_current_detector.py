from pathlib import Path
import tempfile
import hashlib
import json
import unittest
from unittest.mock import patch
import numpy as np
from pipeline.build_dataset import FEATURES
from pipeline.current_detector import current_windows, choose_threshold, evaluate

class CurrentDetectorTests(unittest.TestCase):
    def test_current_labels_do_not_require_future_labels_or_warmup(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'c.pcap';path.write_bytes(b'fixture')
            path.with_suffix('.window-labels.json').write_text(json.dumps({'capture_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'labels':[1,-1,0,1]}))
            states=[{f:float(i) for f in FEATURES} for i in range(4)]
            with patch('pipeline.current_detector.pcap_states',return_value=states):
                data=current_windows('c',Path(directory))
            self.assertEqual(data['window_index'].tolist(),[0,2])
            self.assertEqual(data['y'].tolist(),[1,0])
            np.testing.assert_array_equal(data['x'][:,0],[0,2])
            path.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'does not match'):
                current_windows('c',Path(directory))

    def test_threshold_cannot_hide_capture_false_positives_in_aggregate(self):
        # One small capture would be all false-positive at a permissive global budget.
        y=np.array([0]*100+[0,1]);p=np.array([.1]*100+[.8,.9])
        data={'y':y,'x':np.ones((102,len(FEATURES))), 'capture_id':np.array(['large']*100+['small']*2)}
        score,threshold=choose_threshold(data,p)
        self.assertGreater(threshold,.8)
        self.assertLessEqual(threshold,.9)
        self.assertEqual(score,1)

    def test_rejected_attacks_remain_in_detection_denominator(self):
        data={'y':np.array([1,1,0]),'x':np.ones((3,len(FEATURES))),'capture_id':np.array(['c']*3)}
        report=evaluate(data,np.array([.9,.9,.1]),.5,np.array([True,False,True]))
        self.assertEqual(report['accepted_detection_fraction_all_positives'],.5)
        self.assertEqual(report['rejected_positive_windows'],1)

    def test_threshold_above_float32_max_can_reject_everything(self):
        data={'y':np.array([0,1]),'x':np.ones((2,len(FEATURES))),'capture_id':np.array(['c','c'])}
        probability=np.array([1, .5],dtype=np.float32)
        score,threshold=choose_threshold(data,probability)
        self.assertGreater(threshold,1)
        self.assertEqual(evaluate(data,probability,threshold,np.ones(2,dtype=bool))['groups']['all']['fp'],0)
