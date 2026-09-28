from pathlib import Path
import tempfile
import unittest

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from pipeline.feature_contract import PCAP_CONTRACT, CSV_CONTRACT, TELEMETRY_CONTRACT, compatibility
from pipeline.pcap_calibration import pcap_states
from pipeline.pcap_replay import StreamingPcapReplay


class FeatureContractTests(unittest.TestCase):
    def test_matching_names_cannot_certify_legacy_or_csv_contract(self):
        self.assertFalse(compatibility(None)['compatible'])
        self.assertFalse(compatibility(CSV_CONTRACT)['compatible'])
        self.assertTrue(compatibility(PCAP_CONTRACT)['compatible'])
        self.assertFalse(compatibility(PCAP_CONTRACT, TELEMETRY_CONTRACT)['compatible'])

    def test_offline_and_streamed_features_match_with_reversals_gaps_and_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            packets = []
            for t, reverse, udp in [(100, False, False), (101, True, False), (105, False, True), (122, False, False)]:
                src, dst = ('10.0.0.2', '10.0.0.1') if reverse else ('10.0.0.1', '10.0.0.2')
                transport = UDP(sport=2345, dport=53) if udp else TCP(sport=443 if reverse else 2345, dport=2345 if reverse else 443, flags='A' if reverse else 'S')
                packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src=src, dst=dst)/transport/Raw(b'evidence')
                packet.time = t
                packets.append(packet)
            wrpcap(str(path), packets)
            offline = pcap_states(path)
            for stride in (5, 10, 60):
                streamed = []
                replay = StreamingPcapReplay(path)
                try:
                    while not replay.complete:
                        streamed.extend(item['features'] for item in replay.advance(stride)['states'])
                finally:
                    replay.close()
                self.assertEqual(offline, streamed)
            self.assertEqual(offline[0]['bwd_packets_sum'], 1)
            self.assertEqual(offline[2]['flow_count'], 0)
            self.assertEqual(offline[0]['duration_mean'], 1)

    def test_csv_sequences_never_bridge_missing_time_windows(self):
        import pandas as pd
        from pipeline.build_dataset import FEATURES, BuildConfig, make_sequences
        rows = []
        for second in [0, 5, 10, 15, 100, 105, 110, 115]:
            rows.append({**{f: float(second) for f in FEATURES}, "stage_id": 0, "attack_fraction": 0,
                         "window_start": pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=second)})
        result = make_sequences(pd.DataFrame(rows), BuildConfig(sequence_length=2, horizon=2))
        self.assertEqual(len(result["x"]), 2)
        self.assertEqual(result["x"][:, 0, 0].tolist(), [0, 100])
        self.assertEqual(result["y_state"][:, -1, 0].tolist(), [15, 115])

    def test_unversioned_checkpoint_cannot_emit_shadow_alert_on_replay(self):
        from backend.inference_service import ReplayInferenceSession
        class Service:
            sequence_length = 1
            available = True
            feature_contract = None
            def predict(self, states, domain):
                return {"forecast": [{"shadow_alert": True}], "uncertainty": {"suppression_reasons": []}}
        result = ReplayInferenceSession(Service()).ingest([{"features": {}}])
        self.assertFalse(result["forecast"][0]["shadow_alert"])
        self.assertIn("feature_contract_unverified", result["uncertainty"]["suppression_reasons"])
