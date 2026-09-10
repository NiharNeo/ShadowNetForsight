# ShadowNet ForeSight

Predictive SOC decision-support prototype for Smart India Hackathon. ShadowNet converts network telemetry into five-second states and uses a multi-head LSTM to forecast three future horizons.

## Current status

- Live PCAP/PCAPNG streaming without future-packet leakage
- Five-day CSE-CIC-IDS2018 training partition with fixed whole-day validation and test
- Multi-horizon attack probability, proxy-stage and future-state heads
- Validation-only temperature calibration, 5% FPR threshold selection, and OOD alert suppression
- LSTM/GRU/TCN/Transformer benchmark plus Integrated Gradients explanations
- Cowrie, NetFlow/IPFIX and optional Kafka ingestion with host/identity graph context
- Signed authentication, viewer/operator/admin RBAC, and hash-chained audit logs
- Monte Carlo structural attack-path intervention simulator

## Honest fixed-test results

| Horizon | F1 | Recall | False-positive rate |
|---|---:|---:|---:|
| +5 s | 5.2% | 3.7% | 1.8% |
| +10 s | 7.5% | 6.7% | 3.3% |
| +15 s | 6.1% | 5.3% | 3.2% |

The static next-window baseline reaches 4.9% F1. The model forecasts 14 of 215 attack onsets early, with 15 seconds median lead. CTU-13 produces 100% false positives; deployment and cross-network generalization claims are disabled.

## Architecture

```text
PCAP / CICFlowMeter CSV / Cowrie / NetFlow / IPFIX / Kafka
        │
        ▼
5-second state aggregation (15 features)
        │
        ├── leakage-safe whole-day dataset builder
        ▼
12-state calibrated temporal encoder
        ├── K=3 attack-risk head
        ├── K=3 proxy-stage head
        └── K=3 future-state head
        │
        ▼
FastAPI + WebSocket/stream ingestion → authenticated SOC dashboard
```

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make test
.venv/bin/python -m scripts.manage_users admin --role admin
make run
```

Open <http://127.0.0.1:8000/>. Use **Start controlled live attack** for server-pushed telemetry, **Run scripted attack demo** for the narrated fixture, or **Upload PCAP for live inference** for the capture path.

The dashboard is readable without an account. Uploads, telemetry ingestion and simulation prompt for an operator/admin login. Tokens expire after one hour; users and hash-chained audit records are stored in `data/shadownet.db`. Set `SHADOWNET_TOKEN_SECRET` to a stable deployment secret so tokens survive restarts.

For a labelled target network, fit a validation-only local probability/threshold profile and place it beside the checkpoint:

```bash
.venv/bin/python -m pipeline.fit_domain_calibration \
  --checkpoint models/cic2018-phase1-lstm/lstm.pt \
  --data data/processed-target-network \
  --domain branch-office-a \
  --output models/cic2018-phase1-lstm/domain_calibrations/branch-office-a.json
```

Pass `calibration_domain` when creating a telemetry stream. Unknown domains are rejected rather than silently using an unrelated local profile.

### Guided PCAP calibration

The dashboard can fit a named local profile from labelled validation captures. Supply at least one known-benign PCAP and one controlled-attack PCAP from the same network. Each file must contain at least 75 seconds of usable traffic, and the combined groups must provide at least five sequences each. The workflow fits per-horizon temperatures, thresholds under the validation false-positive-rate budget, and local OOD boundaries.

Keep the PCAP used for final evaluation completely separate. After fitting, select the profile under **Profile for live PCAP** and upload that untouched test capture. A local profile improves calibration for its named network; it does not retrain the temporal model or prove generalization.

## Live telemetry

Create a stream with `POST /api/telemetry/streams`, then send Cowrie JSON or decoded NetFlow v5/v9/IPFIX records to `POST /api/telemetry/streams/{id}/events`. Connect a Kafka JSON topic with `POST /api/telemetry/streams/{id}/kafka`; the background consumer uses bounded polling and feeds the same event-time path. Event-time windows use configurable lateness and feed the same calibrated forecast path as PCAP replay. Responses include host-peer fanout, east-west traffic, authentication failures, and reused-identity context.

### Controlled live attack lab

`POST /api/live-lab` creates an authenticated, finite live session. `/ws/live-lab/{id}` then pushes a new five-second model window every 900 ms through four phases: baseline, service discovery, authentication pressure and internal pivot. These events use the production telemetry adapters, event-time windowing, host graph and trained inference session; they do not replay a PCAP.

This mode deliberately generates synthetic NetFlow and Cowrie records only. It sends no packets, accepts no target address and cannot attack an external system. For a real owned lab, connect an exporter, honeypot or Kafka topic through the telemetry APIs and keep the capture network isolated.

## Run with Docker

```bash
docker build -t shadownet-foresight .
docker run --rm -p 8000:8000 shadownet-foresight
```

The image contains the promoted checkpoint and compact evaluation evidence, but excludes raw and processed datasets.

## Reproduce the experiment

Dataset partitions and byte sizes are declared in `datasets/cic2018_multiday_split.json`. Place the official CSVs under `data/raw/cic2018/`, then run:

```bash
make build-multiday
.venv/bin/python -m pipeline.train_baseline --data data/processed-cic2018-multiday --output models/cic2018-multiday-baseline
make train-multiday
make evaluate-multiday
```

No sequence crosses a file/day boundary. Feature normalization is fitted on training data and thresholds on validation data. The Friday test day is not used for model selection. CTU-13 is diagnostic, not a tuning set.

### Build a labelled raw PCAP corpus

Before acquiring an official CSE-CIC-IDS2018 capture, run:

```bash
make preflight-pcap-acquisition
```

This reports the exact public S3 object, archive size, conservative working-space requirement and download command. A non-zero result means acquisition must wait for more storage. Source sizes and the selection rationale are recorded in `datasets/cicids2018_raw_pcap_sources.json`.

Copy `datasets/pcap_training_plan.example.json` to `datasets/pcap_training_plan.json`, then replace every example path, SHA-256 value and timeline with independently reviewed capture metadata. Keep complete captures in separate train, validation and test partitions. Build the dataset with:

```bash
make build-pcap-corpus
```

The builder rejects missing or changed files, incomplete or overlapping timelines, inconsistent benign/attack stages and captures shorter than the configured sequence plus forecast horizon. Existing dashboard uploads are not training data because they do not have trusted labels or partition provenance.

After the corpus builds successfully, train and evaluate the onset-aware research candidate with:

```bash
make train-pcap-onset
make evaluate-pcap-onset
```

The onset-aware configuration increases the loss applied to labelled benign-to-attack transitions. It does not change the fixed test partition or relax the 5% validation false-positive-rate budget.

## Judge demo flow

1. Show the forecast horizons and fixed-test evidence panel.
2. Start the narrated replay to explain the workflow.
3. Upload `data/demo/demo_attack.pcap` to demonstrate packet-gated inference and warm-up.
4. Point out live Integrated Gradients feature and temporal bars.
5. Show `CLAIMS RESTRICTED` and the CTU-13 failure.
6. Run a defence simulation and inspect the changed topology edges and confidence interval.

## Limitations

- CIC traffic-family labels map to proxy stages, not native MITRE ground truth.
- Recall on the fixed test day remains low.
- CTU-13 shows severe cross-network domain shift.
- Integrated Gradients measures model attribution, not causality.
- The intervention engine is structural and simulation-based, but its edge probabilities are assumptions rather than experimentally identified causal effects.

The full report is generated at `data/evaluation/cic2018-multiday-with-ctu13.json`. Compact dashboard evidence lives beside the promoted checkpoint.

The complete implementation/evidence matrix is documented in [PHASES.md](PHASES.md). A 21-feature graph-aware candidate is retained for research but is not promoted because its fixed-test score regressed. The real Cowrie integration sample comes from the CC BY 4.0 [IEEE SRDS 2025 Shell Honeypot Attack Dataset](https://github.com/zyw-286/shell-attack-evolution-dataset/tree/main/dataset); its exact source and SHA-256 are recorded in `datasets/cowrie_srds2025_sample.json`.
