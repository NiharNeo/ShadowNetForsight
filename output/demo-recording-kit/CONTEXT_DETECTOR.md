# Context-aware detector — 28 September 2026

The causal connection-context component has now been incorporated into a separately trained random-forest candidate. It was **not promoted**: adding context did not resolve the measured false-positive problem.

## Implementation and experiment

`pipeline/context_detector.py` jointly extracts the original 31 packet-window features and nine past-only connection features in one PCAP pass. Unknown-labelled history remains observable traffic, but unknown current targets are excluded. Labels are not features. Context resets at every capture, next-window packets are excluded from completed-window snapshots, and the final incomplete window is excluded.

The new contract is `shadownet.packet-context-window.v1`. The artifact records all 40 feature names, a 60-second context span and a 500,000-packet context limit. An initial extraction stopped on the busy Echo capture at the original 100,000-packet bound. The bound was explicitly raised before fitting; no overflow packets were silently dropped. This larger bound is a research configuration, not a measured production memory or throughput guarantee.

Training/validation capture assignments and random-forest settings remain those of expanded detector v2. Validation selects the threshold and OOD profile. The test captures were already inspected and motivated this change; the comparison is diagnostic only, not fresh independent release evidence. The live checkpoint remains unchanged.

## Result on the same inspected test

| Measurement | Frozen v2 | Context-aware candidate |
|---|---:|---:|
| Detected malicious windows, before rejection | 1,326 / 1,326 | 1,326 / 1,326 |
| Raw false positives | 25 | 28 |
| Aggregate raw FPR | 1.62% | 1.81% |
| Mirai-session raw FPR | 22.94% | 22.94% |
| Benign Somfy session false positives | 0 | 3 |
| Accepted detections / all malicious windows | 94.19% | 94.19% |
| OOD rejection | 3.10% | 3.24% |

Context validation F1 was 99.93%, yet test errors persisted. Only two of the 25 previously identified false-positive vectors still exactly match malicious training vectors when all 40 features are compared against the expanded training set. Resolving exact collisions was necessary for distinguishing many examples, but it was not sufficient for the fitted model to learn a reliable decision boundary.

**Decision:** retain as an unsuccessful research candidate; do not deploy or advertise it as a detection fix. No threshold was changed after seeing test results. This is current-window detection, not attack forecasting or proof of early warning.

## Next data decision

The remaining problem should be addressed through training examples, especially benign Linux/TCP connection retries and mixed benign/malicious sessions. The existing benign training devices and attack scenarios remain a narrow sample. Further feature additions alone are not justified by this result.

For a new data revision, previously inspected captures may be explicitly retired from test status and reassigned as development data, but any claimed final evaluation must use new, independently held-out sessions. The current v2 plan forbids such reassignment; use a clearly versioned replacement plan rather than changing or erasing historical results. Reserve both benign and malicious fresh sessions before fitting, retain per-capture error gates, and document device overlap. If suitable reviewed captures are unavailable, collect representative traffic on an authorized isolated lab network.

## Reproduce

```sh
.venv-enterprise/bin/python -m scripts.train_context_detector
.venv-enterprise/bin/python -m unittest discover -s tests
```

Candidate: `models/iot23-context-detector/random_forest.joblib`.
Evidence: `docs/release-evidence/context-detector.json`.
The artifact is separate from every prior checkpoint and contains `operational_claims_allowed: false`.

Validation: 115 automated tests passed. The new joint-extraction test verifies exact parity of the first 31 features with the existing extractor, correct label alignment through unknown windows, capture reset, next-window exclusion and capture-hash mismatch rejection. Earlier context tests cover chronology, bounded-state overflow, SYN-ACK exclusion and eviction.
