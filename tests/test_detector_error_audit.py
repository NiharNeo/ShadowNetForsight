from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from scripts.audit_detector_errors import read_details, matching_rows
from scripts.ablate_device_features import selected_features, EXCLUDED
from pipeline.build_dataset import FEATURES

class DetectorErrorAuditTests(unittest.TestCase):
    def test_audit_preserves_labels_and_distinguishes_tolerance(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'labels'
            path.write_text('#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration label\n100 flow a 1 b 2 tcp 1 Benign\n')
            flows=read_details(path)
            packet=SimpleNamespace(src='b',src_port=2,dst='a',dst_port=1,protocol=6,timestamp=101.0005)
            self.assertEqual(matching_rows(packet,flows),[])
            self.assertEqual(matching_rows(packet,flows,.001)[0]['label'],'Benign')

    def test_ablation_feature_order_matches_training_projection(self):
        names,indices=selected_features()
        self.assertEqual(names,[FEATURES[i] for i in indices])
        self.assertFalse(set(names)&set(EXCLUDED))
        self.assertEqual(len(names),len(FEATURES)-3)
