from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from scapy.all import IP, TCP, Ether, wrpcap

from pipeline.build_dataset import BuildConfig, FEATURES, aggregate_windows, build
from pipeline.stage_mapping import map_label
from pipeline.pcap_replay import StreamingPcapReplay
from pipeline.train_baseline import train
from pipeline.train_lstm import TrainingConfig, onset_weights, train as train_lstm
from backend.inference_service import LSTMInferenceService
from pipeline.evaluate import early_warning, evaluate
from pipeline.build_partitioned_dataset import build_partitioned
from pipeline.build_pcap_dataset import build as build_pcap_dataset
from scripts.generate_demo_flows import generate
from pipeline.calibration import fit_ood_profile, ood_scores
from pipeline.temporal_model import build_temporal_model
from pipeline.telemetry import StreamingTelemetry, adapt_cowrie, adapt_message, adapt_netflow
from backend.security import Principal, SecurityManager
from pipeline.mitigation_simulator import simulate_mitigation
from pipeline.host_graph import HostGraphTracker
from pipeline.fit_domain_calibration import fit_domain_calibration
from scripts.validate_cowrie_sample import validate as validate_cowrie_sample


class StageMappingTests(unittest.TestCase):
    def test_expected_families(self) -> None:
        self.assertEqual(map_label("Benign")[0], "Normal")
        self.assertEqual(map_label("SSH-Bruteforce")[0], "Initial Access")
        self.assertEqual(map_label("Infiltration")[0], "Reconnaissance")
        self.assertEqual(map_label("Infilteration")[0], "Reconnaissance")
        self.assertEqual(map_label("DoS attacks-Hulk")[0], "Command and Control")
        self.assertEqual(map_label("From-Botnet-V42-TCP-CC1")[0], "Command and Control")
        self.assertEqual(map_label("To-Botnet-V42-TCP-Established")[0], "Normal")


class DatasetBuildTests(unittest.TestCase):
    def test_network_interventions_reduce_simulated_compromise(self) -> None:
        results = [simulate_mitigation(action, trials=3000) for action in ("block_ip", "close_port", "isolate_host", "rate_limit")]
        self.assertTrue(all(result["after"] < result["before"] for result in results))
        self.assertTrue(all(result["method"].startswith("monte_carlo") for result in results))

    def test_host_graph_tracks_peer_fanout_and_identity_reuse(self) -> None:
        tracker = HostGraphTracker()
        tracker.update([
            adapt_cowrie({"eventid": "cowrie.login.failed", "timestamp": 1, "src_ip": "192.0.2.1", "dst_ip": "10.0.0.5", "username": "root"}),
            adapt_cowrie({"eventid": "cowrie.login.failed", "timestamp": 2, "src_ip": "192.0.2.2", "dst_ip": "10.0.0.5", "username": "root"}),
        ])
        context = tracker.features()
        self.assertEqual(context["identity_reuse_count"], 1)
        self.assertEqual(context["top_hosts"][0]["host"], "10.0.0.5")

    def test_security_tokens_rbac_and_hash_chained_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            security = SecurityManager(Path(directory) / "security.db", secret="test-secret")
            security.create_user("analyst", "correct-horse-battery", "operator")
            token = security.authenticate("analyst", "correct-horse-battery")
            self.assertIsNotNone(token)
            self.assertEqual(security.verify_token(token), Principal("analyst", "operator"))
            self.assertIsNone(security.authenticate("analyst", "incorrect-password"))
            security.audit("analyst", "POST", "/api/replays", 200)
            security.audit("analyst", "DELETE", "/api/replays/1", 200)
            entries = security.audit_entries()
            self.assertEqual(entries[0]["previous_hash"], entries[1]["entry_hash"])
            self.assertTrue(security.verify_audit_chain()["valid"])

    def test_all_temporal_architectures_share_output_contract(self) -> None:
        for architecture in ("lstm", "gru", "tcn", "transformer"):
            model = build_temporal_model({"architecture": architecture, "feature_count": 15, "stage_count": 6, "horizon": 3, "hidden_size": 16, "layers": 1, "dropout": 0.1})
            output = model(torch.zeros(2, 12, 15))
            self.assertEqual(output["attack_logits"].shape, (2, 3))
            self.assertEqual(output["stage_logits"].shape, (2, 3, 6))
            self.assertEqual(output["future_state"].shape, (2, 3, 15))

    def test_ood_profile_flags_shifted_sequences(self) -> None:
        train = np.zeros((20, 4, 3), dtype=np.float32)
        validation = np.zeros((10, 4, 3), dtype=np.float32)
        profile = fit_ood_profile(train, validation)
        shifted = np.full((2, 4, 3), 20.0, dtype=np.float32)
        scores = ood_scores(shifted, profile["lower"], profile["upper"])
        self.assertTrue(np.all(scores > profile["threshold"]))

    def test_aggregate_windows_skips_empty_time_bins(self) -> None:
        flows = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-01-01 00:00:00", "2026-01-01 00:01:00"]),
            "stage": ["Normal", "Reconnaissance"],
            "ack_count": [1.0, 0.0], "syn_count": [0.0, 1.0],
            "src_ip": ["a", "b"], "dst_ip": ["c", "d"],
            "dst_port": [80, 22], "protocol": [6, 6],
            "duration": [1.0, 2.0], "fwd_packets": [1.0, 2.0],
            "bwd_packets": [1.0, 0.0], "fwd_bytes": [10.0, 20.0],
            "bwd_bytes": [5.0, 0.0], "iat_mean": [1.0, 2.0],
            "rst_count": [0.0, 0.0], "psh_count": [0.0, 0.0],
            "is_attack": [0.0, 1.0], "raw_label": ["Benign", "Recon"],
        })
        windows = aggregate_windows(flows, 5)
        self.assertEqual(len(windows), 2)
        self.assertEqual(windows["stage"].tolist(), ["Normal", "Reconnaissance"])

    def test_builds_chronological_non_overlapping_splits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flows.csv"
            output = root / "processed"
            generate(source)
            manifest = build([source], output, BuildConfig(sequence_length=6, horizon=3))
            self.assertEqual(len(manifest["features"]), len(FEATURES))
            splits = {name: np.load(output / f"{name}.npz") for name in ("train", "validation", "test")}
            self.assertLess(splits["train"]["anchor_time"][-1], splits["validation"]["anchor_time"][0])
            self.assertLess(splits["validation"]["anchor_time"][-1], splits["test"]["anchor_time"][0])
            self.assertEqual(splits["train"]["x"].shape[1:], (6, len(FEATURES)))
            self.assertEqual(splits["test"]["y_stage"].shape[1], 3)
            self.assertTrue((output / "network_states.csv").exists())

    def test_partitioned_builder_preserves_file_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            partitions = {}
            for name in ("train", "validation", "test"):
                path = raw / f"{name}.csv"
                generate(path, seconds=180)
                partitions[name] = [{"key": path.name, "bytes": path.stat().st_size, "attacks": []}]
            plan = root / "plan.json"
            plan.write_text(json.dumps({"dataset": "fixture", "strategy": "whole files", "partitions": partitions}), encoding="utf-8")
            report = build_partitioned(plan, raw, root / "processed", BuildConfig(sequence_length=6, horizon=3))
            self.assertEqual(report["split_sizes"]["train"], report["split_sizes"]["test"])
            with np.load(root / "processed" / "train.npz") as train_split:
                self.assertEqual(train_split["x"].shape[1], 6)

    def test_trains_and_exports_static_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flows.csv"
            processed = root / "processed"
            models = root / "models"
            generate(source, seconds=600)
            build([source], processed, BuildConfig(sequence_length=6, horizon=3))
            report = train(processed, models)
            self.assertEqual(report["model"], "static_logistic_regression_baseline")
            self.assertIn("test", report["splits"])
            self.assertIn("f1", report["splits"]["test"]["binary"])
            self.assertTrue((models / "baseline.joblib").exists())
            self.assertTrue((models / "metrics.json").exists())

    def test_trains_multi_head_lstm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flows.csv"
            processed = root / "processed"
            models = root / "lstm"
            generate(source, seconds=600)
            build([source], processed, BuildConfig(sequence_length=6, horizon=3))
            report = train_lstm(
                processed,
                models,
                TrainingConfig(epochs=3, patience=2, hidden_size=8, layers=1, batch_size=64),
            )
            self.assertEqual(report["model"], "multi_head_lstm_world_model")
            self.assertEqual(len(report["test"]["horizons"]), 3)
            self.assertTrue((models / "lstm.pt").exists())
            self.assertTrue((models / "history.json").exists())
            calibration_path = models / "domain_calibrations" / "lab-a.json"
            profile = fit_domain_calibration(models / "lstm.pt", processed, "lab-a", calibration_path)
            self.assertEqual(profile["fit_partition"], "validation")
            service = LSTMInferenceService(models / "lstm.pt")
            self.assertIn("lab-a", service.domain_calibrations)
            with np.load(processed / "test.npz") as split:
                states = [dict(zip(service.features, row)) for row in split["x"][0]]
            prediction = service.predict(states)
            self.assertEqual(len(prediction["forecast"]), 3)
            self.assertEqual(prediction["source"], "trained_lstm")
            self.assertIn("uncertainty", prediction)
            self.assertEqual(prediction["explanation_method"], "integrated_gradients_zero_mean_baseline")
            self.assertEqual(len(prediction["temporal_contributions"]), 6)
            domain_prediction = service.predict(states, "lab-a")
            self.assertTrue(domain_prediction["calibration_profile_applied"])
            self.assertEqual(domain_prediction["calibration_domain"], "lab-a")

            baseline_dir = root / "baseline"
            train(processed, baseline_dir)
            evaluation = evaluate(processed, models / "lstm.pt", baseline_dir / "baseline.joblib", root / "evaluation.json", 0.5)
            self.assertEqual(len(evaluation["horizons"]), 3)
            self.assertIn("brier_score", evaluation["horizons"][0])
            self.assertFalse(evaluation["claims_allowed"])

    def test_early_warning_collapses_overlapping_targets(self) -> None:
        split = {
            "anchor_time": np.asarray(["2026-01-01 10:00:00", "2026-01-01 10:00:05"], dtype="U32"),
            "y_attack": np.asarray([[0, 1], [1, 1]], dtype=np.float32),
        }
        probability = np.asarray([[0.1, 0.9], [0.8, 0.9]], dtype=np.float32)
        result = early_warning(split, probability, window_seconds=5, threshold=0.5)
        self.assertEqual(result["attack_onsets"], 1)
        self.assertEqual(result["onsets_forecast_early"], 1)
        self.assertEqual(result["max_lead_seconds"], 10.0)

    def test_onset_weights_only_emphasize_benign_to_attack_transitions(self) -> None:
        split = {
            "anchor_attack": np.asarray([0, 1, 0], dtype=np.float32),
            "y_attack": np.asarray([[0, 1, 1], [1, 1, 0], [1, 0, 1]], dtype=np.float32),
        }
        weights = onset_weights(split, 4.0)
        self.assertEqual(weights.tolist(), [[1.0, 5.0, 1.0], [1.0, 1.0, 1.0], [5.0, 1.0, 5.0]])

    def test_early_warning_resets_between_captures(self) -> None:
        split = {
            "capture_id": np.asarray(["a", "b"], dtype="U1"),
            "anchor_time": np.asarray(["2026-01-01 10:00:00", "2026-01-01 10:00:00"], dtype="U32"),
            "y_attack": np.asarray([[0, 0], [1, 1]], dtype=np.float32),
        }
        probability = np.asarray([[0.1, 0.1], [0.9, 0.9]], dtype=np.float32)
        result = early_warning(split, probability, window_seconds=5, threshold=0.5)
        self.assertEqual(result["attack_onsets"], 0)


class PcapReplayTests(unittest.TestCase):
    def test_labelled_pcap_builder_preserves_capture_partitions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partitions = {}
            for partition_index, partition in enumerate(("train", "validation", "test")):
                path = root / f"{partition}.pcap"
                packets = []
                for index in range(20):
                    packet = Ether() / IP(src="192.0.2.1", dst="10.0.0.5", ttl=50 + partition_index) / TCP(sport=40000, dport=20 + index, flags="S")
                    packet.time = 1000 + partition_index * 1000 + index * 5
                    packets.append(packet)
                wrpcap(str(path), packets)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                partitions[partition] = [{
                    "path": str(path), "sha256": digest,
                    "timeline": [
                        {"start_seconds": 0, "end_seconds": 50, "label": 0, "stage": "Normal"},
                        {"start_seconds": 50, "end_seconds": 100, "label": 1, "stage": "Reconnaissance"},
                    ],
                }]
            plan = root / "plan.json"
            plan.write_text(json.dumps({"dataset": "pcap fixture", "window_seconds": 5,
                                        "sequence_length": 6, "horizon": 2,
                                        "partitions": partitions}), encoding="utf-8")
            output = root / "processed"
            manifest = build_pcap_dataset(plan, output)
            self.assertEqual(manifest["partitions"]["train"]["sequences"], 13)
            self.assertFalse(manifest["feature_observed"]["failed_auth_count"])
            self.assertTrue(manifest["feature_observed"]["ttl_mean"])
            with np.load(output / "test.npz") as split:
                self.assertEqual(split["x"].shape, (13, 6, len(FEATURES)))
                self.assertTrue(np.all(split["capture_id"] == "test.pcap"))
                self.assertGreater(split["y_attack"].sum(), 0)
                self.assertIn("anchor_attack", split.files)
                self.assertIn("anchor_time", split.files)

    def test_packet_level_security_features(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "features.pcap"
            packets = []
            for index, port in enumerate((20, 21, 22)):
                packet = Ether() / IP(src="192.0.2.1", dst="10.0.0.5", ttl=40 + index) / TCP(sport=40000, dport=port, flags="SF", window=2048, seq=100 + index) / b"probe"
                packet.time = 1000 + index
                packets.append(packet)
            wrpcap(str(path), packets)
            replay = StreamingPcapReplay(path)
            state = replay.advance(5)["states"][0]["features"]
            self.assertEqual(state["fin_count"], 3.0)
            self.assertGreater(state["ttl_variance"], 0.0)
            self.assertEqual(state["tcp_window_mean"], 2048.0)
            self.assertEqual(state["payload_size_mean"], 5.0)
            self.assertEqual(state["sequential_port_ratio"], 1.0)

    def test_real_cowrie_sample_ingests_when_available(self) -> None:
        path = Path("data/raw/cowrie-srds2025-sample.jsonl")
        if not path.exists():
            self.skipTest("Optional provenance-tracked Cowrie sample not downloaded")
        report = validate_cowrie_sample(path)
        self.assertEqual(report["records"], 300)
        self.assertEqual(report["unknown_address_events"], 0)
        self.assertGreater(report["emitted_states"], 0)

    def test_telemetry_adapters_and_event_time_windows(self) -> None:
        cowrie = adapt_cowrie({"eventid": "cowrie.login.failed", "timestamp": "2026-01-01T00:00:01Z",
                               "src_ip": "192.0.2.5", "dst_ip": "10.0.0.5", "username": "root"})
        self.assertEqual(cowrie.identity, "root")
        self.assertEqual(cowrie.outcome, "failure")
        flow = adapt_netflow({"timestamp": cowrie.timestamp + 7, "IPV4_SRC_ADDR": "192.0.2.5",
                              "IPV4_DST_ADDR": "10.0.0.5", "L4_DST_PORT": 22,
                              "PROTOCOL": 6, "IN_PKTS": 4, "IN_BYTES": 240, "TCP_FLAGS": 2})
        self.assertEqual(flow.packets, 4)
        self.assertEqual(flow.syn, 1)
        self.assertEqual(adapt_message(json.dumps({"eventid": "cowrie.login.success", "timestamp": cowrie.timestamp})).source, "cowrie")

        stream = StreamingTelemetry(window_seconds=5, allowed_lateness=0)
        result = stream.ingest([flow, cowrie])
        self.assertEqual(result["states"][0]["packet_count"], 1)
        self.assertEqual(result["states"][0]["features"]["unique_src_ips"], 1.0)
        self.assertEqual(result["states"][0]["features"]["failed_auth_count"], 1.0)
        self.assertEqual(result["states"][0]["features"]["unique_host_edges"], 1.0)
        flushed = stream.ingest([], flush=True)
        self.assertEqual(flushed["states"][0]["packet_count"], 4)
        late = stream.ingest([cowrie])
        self.assertEqual(late["events_rejected_late"], 1)

    def test_future_packets_do_not_leak_into_current_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "timed.pcap"
            packets = []
            for timestamp, port in ((1000.0, 80), (1002.0, 81), (1012.0, 445)):
                packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.10", dst="10.0.0.5") / TCP(sport=40000, dport=port, flags="S")
                packet.time = timestamp
                packets.append(packet)
            wrpcap(str(path), packets)

            replay = StreamingPcapReplay(path, window_seconds=5)
            first = replay.advance(5)
            self.assertEqual(first["processed_packets"], 2)
            self.assertEqual(first["states"][0]["packet_count"], 2)
            self.assertEqual(first["states"][0]["features"]["unique_dst_ports"], 2.0)
            self.assertFalse(first["complete"])

            second = replay.advance(5)
            self.assertEqual(second["processed_packets"], 2)
            self.assertEqual(second["states"][0]["packet_count"], 0)

            third = replay.advance(5)
            self.assertEqual(third["processed_packets"], 3)
            self.assertEqual(third["states"][0]["features"]["unique_dst_ports"], 1.0)
            self.assertTrue(third["complete"])


if __name__ == "__main__":
    unittest.main()
