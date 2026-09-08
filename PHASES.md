# ShadowNet improvement phases

## Phase 1 — model credibility

- Five whole CSE-CIC-IDS2018 training days cover brute force, DoS/DDoS, infiltration and benign traffic. Separate whole days are reserved for validation and test.
- Per-horizon temperature and decision thresholds are fitted on validation only. Threshold search maximizes F1 subject to a 5% validation false-positive-rate budget.
- `pipeline.fit_domain_calibration` creates named target-network profiles from that network's validation partition. Telemetry streams select a known profile explicitly.
- Quantile OOD profiles suppress alerts outside the training envelope. CTU-13 remains diagnostic only and is never used for selection.

## Phase 2 — temporal and graph models

- The shared forecast contract supports LSTM, GRU, causal TCN and Transformer encoders. The benchmark records eight fixed candidates.
- State vectors now include directed host edges, fanout, fan-in, east-west ratio, failed authentication and identity reuse.
- A 21-feature graph-aware LSTM was trained and evaluated at `models/cic2018-graph-lstm`. It was not promoted because fixed-test macro F1 fell to 3.86%, below the promoted 15-feature checkpoint. Unobserved CIC identity fields are masked so random weights cannot react to them.

## Phase 3 — explanations

- Runtime and training reports use Integrated Gradients from the normalized training-mean baseline, with feature and time-step attribution.
- Attributions are explicitly described as model sensitivity, not causal evidence.

## Phase 4 — telemetry

- Cowrie and decoded NetFlow v5/v9/IPFIX aliases normalize into one canonical event contract.
- HTTP batches and a real Kafka consumer use event-time windows, configurable lateness and late-event rejection.
- A provenance-tracked 300-record public Cowrie sample produces 281 five-second states with no unknown endpoints. See `datasets/cowrie_srds2025_sample.json`.

## Phase 5 — application security

- PBKDF2 password hashing, HMAC-signed one-hour tokens and viewer/operator/admin role gates protect state-changing APIs.
- SQLite audit records form a verifiable HMAC hash chain. The signing secret persists with owner-only filesystem permissions.
- WebSockets authenticate in their first message so bearer tokens do not appear in URLs.

## Phase 6 — mitigation simulation

- A structural attack-path graph replaces fixed outcome lookups.
- Each action changes declared edge probabilities and runs 20,000 deterministic Monte Carlo trials with 95% intervals.
- Results remain conditional scenario estimates; edge probabilities have not been experimentally identified as causal effects.

## Verification and honest deployment status

- `python -m unittest discover -s tests -v`: 16 tests passing.
- Real Cowrie integration report: `data/evaluation/cowrie-srds2025-ingestion.json`.
- Graph candidate evaluation: `data/evaluation/cic2018-graph-with-ctu13.json`.
- Deployment claims remain restricted. The promoted checkpoint has low fixed-test recall, and both promoted and graph candidates show 100% raw CTU-13 false positives; OOD rejection suppresses those external-network alerts.
