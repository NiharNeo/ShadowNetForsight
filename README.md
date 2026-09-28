# ShadowNet ForeSight

Predictive SOC decision-support prototype for Smart India Hackathon. ShadowNet converts network telemetry into five-second states and uses a multi-head LSTM to forecast three future horizons.

## Two-day SIH demo

With Docker Desktop running and the prepared Python environment:

```sh
make demo-up
```

Open http://localhost:8000. Private demo credentials are in `data/demo/access.json`.
Upload either three-minute synthetic fixture from `data/demo/captures/` to exercise
the trained model. Use `make demo-status` and `make demo-stop` to manage the isolated
demo deployment. Run `.venv-enterprise/bin/python scripts/verify_demo.py` to verify
HTTP authentication, WebSocket replay, simulation and token revocation.

See [the recording runbook](docs/DEMO_VIDEO_RUNBOOK.md) for the narration, rehearsal
checklist and two-day schedule. Operational model validation remains a later gate.

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
python3.12 -m venv .venv-enterprise
.venv-enterprise/bin/python -m pip install --upgrade pip==26.2.1
.venv-enterprise/bin/python -m pip install -r requirements.txt
make test
.venv-enterprise/bin/python -m scripts.manage_users admin --role admin
make run
```

Open <http://127.0.0.1:8000/>. Use **Start attack replay** for the narrated fixture or **Upload PCAP for live inference** for the trained-model path.

The dashboard is readable without an account. Uploads, telemetry ingestion and simulation require an operator/admin login. Calibration changes and approved Kafka connections require an admin. Tokens expire after one hour; users and hash-chained audit records are stored in `data/shadownet.db`. Set `SHADOWNET_TOKEN_SECRET` to a stable deployment secret. Logout or password replacement revokes existing tokens. Login attempts are rate-limited. The browser retains its token only in memory.

For a labelled target network, fit a validation-only local probability/threshold profile and place it under the configured data directory (`data/calibrations` by default):

```bash
.venv-enterprise/bin/python -m pipeline.fit_domain_calibration \
  --checkpoint models/cic2018-phase1-lstm/lstm.pt \
  --data data/processed-target-network \
  --domain branch-office-a \
  --output data/calibrations/branch-office-a.json
```

Pass `calibration_domain` when creating a telemetry stream. Unknown domains are rejected rather than silently using an unrelated local profile.

### Guided PCAP calibration

The dashboard can fit a named local profile from labelled validation captures. Supply at least one known-benign PCAP and one controlled-attack PCAP from the same network. Each file must contain at least 75 seconds of usable traffic, and the combined groups must provide at least five sequences each. The workflow fits per-horizon temperatures, thresholds under the validation false-positive-rate budget, and local OOD boundaries.

Keep the PCAP used for final evaluation completely separate. After fitting, select the profile under **Profile for live PCAP** and upload that untouched test capture. A local profile improves calibration for its named network; it does not retrain the temporal model or prove generalization.

## Live telemetry

Create a stream with `POST /api/telemetry/streams`, then send Cowrie JSON or decoded NetFlow v5/v9/IPFIX records to `POST /api/telemetry/streams/{id}/events`. Connect a Kafka JSON topic with `POST /api/telemetry/streams/{id}/kafka`; the background consumer uses bounded polling and feeds the same event-time path. Event-time windows use configurable lateness and feed the same calibrated forecast path as PCAP replay. Responses include host-peer fanout, east-west traffic, authentication failures, and reused-identity context.

### Offline controlled-lab pilot

Run `make controlled-lab-pilot` to create two synthetic 15-minute PCAP fixtures and a SHA-256 manifest under `data/controlled-lab/pilot`. The generator writes packets directly to disk and transmits nothing. The benign capture represents ordinary DNS, HTTPS and SSH administration; the attack-progression capture contains a benign warm-up, service discovery and SSH connection pressure.

These files validate ingestion, timing, feature extraction and labelling only. They are not representative deployment evidence and must not replace independently collected train, validation and held-out test sessions from the owned target network.

### Automated validation and training workflow

Run `make workflow-check` for the fast gate used by continuous integration. It regenerates the offline pilot, verifies every capture hash and usable window count, runs unit and API integration tests, and writes `data/workflow/latest.json`.

Run `make workflow-full` only after `datasets/pcap_training_plan.json` contains at least 18 independent training captures, 6 validation captures and 6 untouched test captures. The full gate rejects missing files, changed hashes, reused captures and missing timelines before it builds the dataset, trains the baseline and GRU model, and evaluates the held-out test partition. GitHub Actions runs the fast gate on pushes and pull requests.

Blockchain is intentionally not part of this architecture. Capture provenance uses SHA-256, while administrative audit records use an HMAC-SHA256 hash chain. A distributed ledger would add operational complexity without improving trust for this single-organization deployment; it can be reconsidered only if independent organizations must jointly attest to evidence.

## Deployment readiness

See [the deployment runbook](docs/DEPLOYMENT.md) for guarded on-premises pilot settings, persistent storage, backup/restore, release gates and remaining blockers. The software is being hardened for a single-organization research pilot. It is **not certified enterprise-ready** and the current model remains unsuitable for autonomous defence.

`GET /api/health` is liveness. `GET /api/ready` checks the model, OOD gate, packaged dashboard data, database and audit integrity, returning HTTP 503 when unavailable. Readiness never grants model-performance claims. Sessions are bounded and expire after 30 minutes without ingestion/advancement. They are process-local and do not survive restarts. Use exactly one worker.

## Run with Docker

```bash
docker build -t shadownet-foresight .
docker run --rm -p 127.0.0.1:8000:8000 -v shadownet-data:/app/data shadownet-foresight
```

The image contains the promoted checkpoint and compact evaluation evidence, but excludes raw and processed datasets.

## Reproduce the experiment

Dataset partitions and byte sizes are declared in `datasets/cic2018_multiday_split.json`. Place the official CSVs under `data/raw/cic2018/`, then run:

```bash
make build-multiday
.venv-enterprise/bin/python -m pipeline.train_baseline --data data/processed-cic2018-multiday --output models/cic2018-multiday-baseline
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
