# Packet-aligned model pilot

This pilot fixes the CSV-to-PCAP feature mismatch in a new research checkpoint. It does **not** promote that checkpoint to the running dashboard or establish production readiness.

## Reproduce

From the repository root, using the existing Python environment:

```sh
.venv-enterprise/bin/python -m scripts.acquire_iot23_pilot
.venv-enterprise/bin/python -m pipeline.build_iot23_dataset
.venv-enterprise/bin/python -m scripts.train_iot23_pilot
.venv-enterprise/bin/python -m unittest discover -s tests
```

The acquisition plan is `datasets/iot23_pilot_sources.json`. The publisher is https://www.stratosphereips.org/datasets-iot23 and the files come from https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/. Version 2 is marked work in progress. Only passive PCAPs, text flow logs and documentation are downloaded; malware binaries are not used. Locally calculated SHA-256 digests track provenance, not publisher authentication.

## Changes

- Training inputs use the actual replay `summarize` and `WindowAccumulator` implementation and `shadownet.packet-window.v1` feature contract.
- Whole captures are assigned to train, validation or test. No windows cross captures. The first two hours are used, excluding the final incomplete target window. Capture hashes prevent duplicate source captures across partitions.
- Publisher flow labels are matched to individual packets by bidirectional endpoints, protocol and timestamp. Unmatched or conflicting packet labels remain unknown. Unknown target/anchor windows are excluded; unknown history observations remain features.
- The two Somfy logs have no label column despite their filenames. Their publisher READMEs explicitly classify those captures as benign. Only packets matching logged flows inherit that documented annotation; unmatched packets remain unknown. This exception is explicit in the acquisition plan. A log without labels otherwise raises an error.
- A window is malicious when it contains a publisher-labelled malicious packet. Empty windows mean no observed malicious packet, not proof the host is safe. Binary labels do not identify MITRE stages or establish compromise.
- A fixed 30-epoch maximum LSTM (32 hidden units, one layer, patience 6, seed 42) is compared with logistic regression. Both use validation-only thresholds with an aggregate 5% false-positive budget. Temperature and OOD threshold also use validation only. Test results do not select weights or thresholds.
- Early-warning evaluation now issues forecasts at the end of the observed window, removing five seconds of incorrectly credited lead time. Gaps in labelled truth cannot create onsets. These are *traffic-window* onsets, often recurrent activity within an already infected capture, not first compromise events.
- Reports retain raw errors, accepted errors, rejected positive and negative targets, per-capture results, and active-anchor results. Missing denominators are null rather than fabricated zero recall.

An initial diagnostic run exposed the incomplete-final-window issue; its outputs were replaced after fixing that boundary, using the same model settings. No hyperparameters were adjusted to improve test results.

## Artifacts

- `data/raw/iot23/acquisition.json`: original URLs, sizes and hashes.
- `data/processed-iot23-pilot/manifest.json`: label coverage, capture partitions, features and limitations.
- `data/pcap-corpus/iot23/`: derived uploadable IP captures and separate window-label mappings. These are research inputs, not guaranteed supported traffic for the old live model. Window mappings are not the dashboard evaluation manifest format.
- `models/iot23-pilot-lstm/lstm.pt`: candidate checkpoint, separate from the live CIC checkpoint.
- `models/iot23-pilot-lstm/baseline.joblib`: comparison model with its validation threshold and log transform.
- `docs/release-evidence/iot23-pilot-evaluation.json`: authoritative evaluation including supports and confusion counts.

## Promotion is blocked

The selected test malware capture's malicious flows all occur within the 60-second warm-up. Its eligible targets contain **no labelled attacks**, so it can test false positives but cannot test attack recall or early warning. Do not describe a low test false-positive rate as successful attack detection. Acquire an additional independent attack capture with activity after warm-up and evaluate the frozen candidate without adjusting it. If subsequent retraining uses those results, reserve fresh captures for the next test.

Other limitations: only a few IoT sessions, publisher labels not independently audited, shared benign device between validation and test, correlated overlapping windows, and many empty windows. Aggregate validation performance can hide high false-positive rates within individual attack sessions. The OOD rate here is measured on this narrow pilot and cannot replace the old model's CTU-13 findings. Production claims require more devices/networks, independently audited labels, a qualified current-window detector, and genuine first-onset evaluation. Keep operational alerts disabled until those checks pass.

## Measured result of the fixed run

The partitions contain 4,239 training, 2,849 validation and 2,829 test sequences. For the next five-second window, the LSTM validation F1 is 97.83%, recall 99.33%, and raw false-positive rate 3.32%; baseline F1 is 96.04%. These are tuning-set results, not independent detection proof.

On the eligible test targets, the LSTM produces 12 false positives out of 2,829 negative targets (0.42% raw false-positive rate). OOD rejects 240/2,829 sequences (8.48%); accepted predictions have 10 false positives out of 2,589 negatives (0.39%). Test recall is unavailable because there are no positive eligible targets. The baseline produces 985 false positives (34.82%).

Validation and test windows overlap and are correlated; these counts do not represent thousands of independent capture trials. The regression suite passes 99 tests. The live dashboard continues to use its existing checkpoint.

## 27 September — independent attack test completed

The frozen checkpoint was evaluated on the first two hours of publisher capture `CTU-IoT-Malware-Capture-3-1` (Muhstik), selected by manageable download size and absence from the original partitions. The available eligible portion yields 1,185 sequences, all with malicious target windows. No fitting, threshold changes or OOD recalibration were performed. Before and after evaluation, checkpoint and baseline hashes must match the pre-recorded supplementary plan.

| Next-window measurement | Result |
|---|---:|
| Raw LSTM detections | 78 / 1,185 (6.58% recall) |
| Raw LSTM misses | 1,107 |
| OOD-rejected malicious targets | 721 / 1,185 (60.84%) |
| Accepted detections / all malicious targets | 41 / 1,185 (3.46%) |
| Accepted-only recall | 41 / 464 (8.84%) |
| Frozen logistic baseline recall | 1,036 / 1,185 (87.43%) |

Longer-horizon raw LSTM recalls are 2.78% and 0%. This capture has no eligible negative targets or benign-to-malicious onsets, so its false-positive rate and early-warning lead are unavailable. Precision of 100% here is not evidence of discrimination: every eligible target is positive. The earlier negative-only test remains necessary and showed the baseline's 34.82% false-positive rate.

**Decision: do not promote either model.** Independent attack recall is now measured and inadequate for the LSTM. The strong validation score did not generalize to this different attack family. The earlier promotion-blocker text records the initial test's limitation; this supplementary result adds a measured failure rather than replacing or erasing that test.

Reproduce (passive downloads only):

```sh
.venv-enterprise/bin/python -m scripts.acquire_iot23_pilot --plan datasets/iot23_supplementary_test.json
.venv-enterprise/bin/python -m scripts.evaluate_iot23_holdout
```

Full evidence: `release-evidence/iot23-supplementary-test.json`. Source URLs and hashes: `data/raw/iot23/iot23_supplementary_test-acquisition.json`. This capture is now an inspected test; do not repeatedly tune against it and still call it untouched.

Next iteration should qualify a current-window detector on broader independent captures before optimizing forecasting. Include normal interactive and high-volume benign sessions, multiple malicious families, and explicit benign warm-up/onset boundaries. Reserve fresh whole captures for the next final test. Set acceptance gates for per-capture false alerts, recall including rejections, and genuine first-onset coverage before evaluation. The live demo remains on its existing checkpoint with operational alerts disabled.

Validation for this update: 101 automated tests passed; Git whitespace checks passed. Model artifacts were unchanged during supplementary evaluation.
