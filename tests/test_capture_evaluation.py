import copy
import unittest
from pipeline.evaluate_capture import evaluate


def artifacts():
    updates = []
    for elapsed in (60, 65, 70, 75):
        updates.append({'elapsed_seconds': elapsed, 'inference': {
            'model_ready': True, 'uncertainty': {'status': 'in_distribution'},
            'feature_compatibility': {'compatible': True},
            'forecast': [{'offset_seconds': offset, 'risk': 10 if elapsed == 65 else 90, 'threshold': 50}
                         for offset in (5,10,15)]}})
    report = {'schema_version': 1, 'capture': {'capture_sha256': 'a'*64, 'checkpoint_sha256': 'b'*64}, 'updates': updates}
    labels = {'sha256': 'a'*64, 'duration_seconds': 80, 'timeline': [
        {'start_seconds': 0, 'end_seconds': 65, 'label': 0},
        {'start_seconds': 65, 'end_seconds': 80, 'label': 1}]}
    return report, labels


class CaptureEvaluationTests(unittest.TestCase):
    def test_future_window_alignment_and_censoring(self):
        report, labels = artifacts()
        result = evaluate(report, labels)
        first = result['horizons'][0]
        self.assertEqual({k:first['raw_classifier'][k] for k in ('support','tp','fp','fn','tn')},
                         {'support':3,'tp':1,'fp':1,'fn':1,'tn':0})
        self.assertEqual(first['outside_observed_capture'], 1)
        self.assertEqual(result['horizons'][1]['raw_classifier']['support'], 2)
        self.assertFalse(result['claims_allowed'])

    def test_rejection_is_not_a_true_negative(self):
        report, labels = artifacts()
        for update in report['updates']:
            update['inference']['uncertainty']['status'] = 'out_of_distribution'
        first = evaluate(report, labels)['horizons'][0]
        self.assertEqual(first['rejection_rate'], 1)
        self.assertEqual(first['rejected_attack'], 2)
        self.assertEqual(first['rejected_benign'], 1)
        self.assertEqual(first['accepted_only']['support'], 0)
        self.assertIsNone(first['accepted_only']['false_positive_rate'])
        self.assertIsNone(first['accepted_only']['recall'])

    def test_matching_contract_is_required_for_accepted_metrics(self):
        report, labels = artifacts()
        for update in report['updates']:
            update['inference']['feature_compatibility']['compatible'] = False
        self.assertEqual(evaluate(report, labels)['horizons'][0]['accepted_only']['support'], 0)

    def test_ambiguous_labels_and_same_label_stage_boundaries(self):
        report, labels = artifacts()
        labels['timeline'][0]['end_seconds'] = 67
        labels['timeline'][1]['start_seconds'] = 67
        self.assertEqual(evaluate(report, labels)['horizons'][0]['ambiguous_label_windows'], 1)
        labels['timeline'] = [{'start_seconds':0,'end_seconds':67,'label':1},
                              {'start_seconds':67,'end_seconds':80,'label':1}]
        first = evaluate(report, labels)['horizons'][0]
        self.assertEqual(first['ambiguous_label_windows'], 0)
        self.assertIsNone(first['raw_classifier']['false_positive_rate'])

    def test_bad_hashes_gaps_and_duplicate_timestamps_are_rejected(self):
        report, labels = artifacts()
        for bad in [{**labels,'sha256':'c'*64}, {**labels,'timeline':[{'start_seconds':1,'end_seconds':80,'label':0}]}]:
            with self.assertRaises(ValueError): evaluate(report, bad)
        report['updates'][1]['elapsed_seconds'] = 60
        with self.assertRaises(ValueError): evaluate(report, labels)

    def test_invalid_scores_and_horizons_are_rejected(self):
        report, labels = artifacts()
        for value in (float('nan'), float('inf'), True, -1, 101):
            bad = copy.deepcopy(report)
            bad['updates'][0]['inference']['forecast'][0]['risk'] = value
            with self.assertRaises(ValueError): evaluate(bad, labels)
        report['updates'][0]['inference']['forecast'][1]['offset_seconds'] = 5
        with self.assertRaises(ValueError): evaluate(report, labels)

    def test_manifest_matches_exactly_one_capture(self):
        report, labels = artifacts()
        self.assertEqual(evaluate(report, {'captures':[labels], 'status':'synthetic'})['label_provenance'], 'synthetic')
        with self.assertRaises(ValueError): evaluate(report, {'captures':[labels,labels]})
