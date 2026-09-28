# Expanded detector experiment v2

This experiment broadens the current-window detector's training data while keeping previously inspected test sessions out of fitting. It does not change the deployed CIC forecasting checkpoint.

## Fixed plan

`datasets/iot23_expanded_v2.json` was written before acquisition and training. All captures use their first two hours, excluding the last incomplete window and unknown labels. The additional training sessions are CTU-IoT-Malware-Capture-1-1 (Hide and Seek) and CTU-Honeypot-Capture-5-1 (Amazon Echo). Original training/validation assignments remain intact. Fresh test sessions are CTU-IoT-Malware-Capture-34-1 (Mirai) and CTU-Honeypot-Capture-7-4 (Somfy). The Somfy device also occurs in validation, so the test is capture-disjoint but not fully device-disjoint.

Data comes from the publisher's passive PCAP and flow-label archive: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/. The publisher marks this version work in progress; labels have not been independently audited. No malware binaries are acquired or executed.

Logistic regression and random forest retain the previous experiment's settings. Model choice and thresholds use validation only, with a 5% false-positive ceiling for each capture and its active-window subset. The selected artifact and its hash are written to `models/iot23-expanded-detector-v2/frozen-selection.json` before test predictions. Only the selected model is evaluated on the fresh test set.

## Research screen, fixed before results

- At least 100 positive and 100 negative test windows.
- At least 80% raw recall.
- Accepted detections must cover at least 70% of all positive windows, including rejected positives in the denominator.
- No more than 5% false positives overall, within each test capture and within each active-window subset.
- No more than 20% rejected windows.

These are research screening criteria, not enterprise acceptance criteria. Passing does not approve operational alerts, establish first-onset forecasting, or prove performance across networks. Only two fresh sessions are included.

## Reproduce

```sh
.venv-enterprise/bin/python -m scripts.acquire_iot23_pilot --plan datasets/iot23_expanded_v2.json
.venv-enterprise/bin/python -m scripts.train_expanded_detector
.venv-enterprise/bin/python -m unittest discover -s tests
```

Acquisition provenance: `data/raw/iot23/iot23_expanded_v2-acquisition.json`.
Evaluation output: `docs/release-evidence/expanded-detector-v2.json`.

The training script rejects duplicate captures, inspected captures labelled as fresh, and reuse of previous test IDs for training. Record any data-quality repairs explicitly. Once test results are inspected, these sessions are no longer fresh for a later model iteration.

## Completed result

Training used 7,118 labelled current windows across five captures; validation used 2,877 windows across two captures. The fresh test contains 2,873 labelled windows across two other captures. Validation selected the random forest. Both models and thresholds were frozen before test predictions; no settings were changed after inspecting this result.

| Fresh-test measurement | Result |
|---|---:|
| Raw detections | 1,326 / 1,326 positives (100% recall) |
| Raw false positives | 25 / 1,547 negatives (1.62%) |
| Aggregate F1 | 99.07% |
| OOD rejection | 89 / 2,873 (3.10%) |
| Accepted detections / all positives | 1,249 / 1,326 (94.19%) |
| Rejected positive / negative windows | 77 / 12 |
| Somfy benign session false positives | 0 / 1,438 |
| Mirai session benign-labelled false positives | 25 / 109 (22.94%) |
| Mirai active benign-labelled false positives | 25 / 40 (62.50%) |

**Research screen failed; no model was promoted.** Recall, rejection and aggregate false-positive criteria passed, but the per-capture false-positive criterion failed. A large benign session must not conceal errors inside the malware-session background traffic. Do not present aggregate F1 alone as release qualification. These windows are correlated and the test has only two sessions; this is not an enterprise or attack-forecasting accuracy claim.

Data-quality note: the new Somfy log lacked a label column. Before scoring, it was assigned the same explicit publisher-declared benign capture policy used in the earlier pilot, applied only to matching logged flows. The Echo training capture had 66 unknown windows; the fresh Mirai capture had four. Unknown current labels were excluded. Capture 1-1's sampled interval is continuously malicious, so it adds detection diversity but does not prove first-onset warning.

The complete report contains source/derived capture hashes, split sizes, implementation hashes, both validation results and the selected model's fresh-test metrics. `expanded-detector-v2-errors.json` records each of the 25 false-positive windows with its observed features for review. Feature importance is diagnostic, not causal evidence.

Next: inspect why benign-labelled traffic inside attack sessions triggers the detector, collect additional mixed benign/malicious sessions, and revise training using reviewed examples while reserving new independent tests. Do not tune the threshold against this now-inspected test. Preserve the original live checkpoint and its research-only status until an explicit model release qualifies.

Validation: 107 automated tests pass. Full passive downloads and hash-tracked derived captures are stored locally; no malware payloads were executed.
