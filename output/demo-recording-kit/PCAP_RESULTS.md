# Uploadable PCAPs and measured results

Use `pilot-benign-3m.pcap` and `pilot-attack-3m.pcap` from this kit. Each is a synthetic 180-packet, three-minute fixture. No network attack was executed to create these files. Their scenario labels describe the generator, not independently verified attack outcomes.

Both files were replayed to completion through the deployed checkpoint's parser and inference implementation in five-second increments. Each produced 25 model-ready updates; all 25 were out of distribution. Operational alerts were disabled. These files demonstrate ingestion, time windows, packet graphs, model execution, explanations and rejection handling. They do **not** demonstrate reliable attack detection, and are not validated model-compatible traffic.

`capture-compatibility.json` contains every model-ready forecast, OOD decision and the checkpoint/file SHA-256 hashes. Reproduce from the repository:

```sh
.venv-enterprise/bin/python -m scripts.audit_demo_captures
.venv-enterprise/bin/python -m scripts.verify_demo
```

The second command checks the running localhost Docker app, authenticated upload, WebSocket replay and token revocation. It signs out the demo account, so run it before recording.

## What can be claimed

- These PCAP formats are readable, reach model readiness and finish replay.
- Graphs show observed traffic, and forecasts are computed by the checkpoint.
- Unknown traffic is flagged. This is rejection, not successful attack detection.

## What remains unproven

The deployed checkpoint has poor held-out early-warning coverage (14/215 onsets) and cannot generalize to the evaluated CTU-13 sample. No independently validated attack PCAP suitable for claiming reliable detection has been established. Selecting only favorable captures or weakening rejection would not resolve this limitation.

To establish detection proof, collect independently labelled captures, match capture feature extraction to the training pipeline, retrain using a train partition, calibrate on validation captures, and publish unchanged performance on held-out captures, including benign false positives and missed attacks.
