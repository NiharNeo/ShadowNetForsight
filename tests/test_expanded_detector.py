import unittest
from scripts.train_expanded_detector import screening, validate_partitions

class ExpandedDetectorTests(unittest.TestCase):
    def test_inspected_capture_cannot_be_called_fresh(self):
        with self.assertRaisesRegex(ValueError,'inspected'):
            validate_partitions({'captures':[{'id':'old','partition':'fresh_test'}]},{'old'})
        with self.assertRaisesRegex(ValueError,'enter training'):
            validate_partitions({'captures':[{'id':'CTU-IoT-Malware-Capture-3-1','partition':'train'}]},set())

    def test_screening_requires_positive_support_and_counts_rejection(self):
        gates=dict(minimum_positive_test_windows=100,minimum_negative_test_windows=100,minimum_raw_recall=.8,minimum_accepted_detection_fraction=.7,maximum_per_capture_fpr=.05,maximum_rejection_rate=.2)
        raw=dict(tp=0,fn=0,tn=1000,fp=0,recall=None,false_positive_rate=0)
        result=dict(groups={'all':raw},accepted_detection_fraction_all_positives=None,ood_rejection_rate=0)
        report=screening(result,gates)
        self.assertFalse(report['passed'])
        self.assertIn('Insufficient positive test windows',report['failures'])
        raw.update(tp=900,fn=100,recall=.9)
        result.update(accepted_detection_fraction_all_positives=.1,ood_rejection_rate=.8)
        self.assertIn('Rejection rate above gate',screening(result,gates)['failures'])
        result.update(accepted_detection_fraction_all_positives=.9,ood_rejection_rate=.1)
        self.assertTrue(screening(result,gates)['passed'])
        self.assertFalse(screening(result,gates)['operational_approval'])
