# Current-window detector experiment — 27 September 2026

This experiment asks whether we can recognize malicious traffic in a completed five-second window, separately from predicting future traffic. It is an offline research experiment, not a deployed detector or an early-warning result.

## Implemented

`pipeline.current_detector` builds examples from the same replay features and hash-matched publisher window labels. Each input is one completed window; there is no 60-second warm-up and no requirement for future labels. Unknown current labels and the last incomplete window are excluded. Future labels, capture IDs and window indices are not model features.

Training remains restricted to the original three training captures. Validation remains restricted to the original two validation captures. We compare logistic regression and a fixed 200-tree random forest (depth 10, minimum leaf size 5, seed 42). Thresholds maximize validation F1 subject to a maximum 5% false-positive rate within **each** validation capture and within each capture's active-window subset. This prevents an aggregate score from hiding errors on smaller captures. OOD profiling uses training/validation only; raw and accepted results remain separate.

All evaluation captures have already been inspected in earlier work. These comparisons are diagnostics, not fresh independent release evidence. No test examples are used for fitting or threshold selection. Both candidate files remain separate from the running model.

## Reproduce

```sh
.venv-enterprise/bin/python -m pipeline.current_detector
.venv-enterprise/bin/python -m unittest discover -s tests
```

Prerequisites are the derived captures and hash-bound window labels from the IoT-23 pilot and supplementary test. See `IOT23_MODEL_PILOT.md` for acquisition and extraction commands.

Authoritative report: `release-evidence/current-detector.json`.
Models: `models/iot23-current-detector/logistic.joblib` and `random_forest.joblib`.

## Interpretation and next step

Validation-based model selection is not permission to promote a model. Current-window detection recovered three malicious test windows previously hidden by the forecasting model's warm-up, making them eligible for evaluation. This is a different target and denominator from the forecasting evaluation; directly comparing its F1 with forecasting F1 would be misleading.

The random forest showed excellent validation performance but poor test generalization. This supports the diagnosis that the narrow training corpus is insufficient; a more complex forecasting model alone will not resolve the measured problem. Do not replace the live checkpoint or hide these failures by recalibrating against test captures.

Next: acquire broader benign and malicious capture sessions; explicitly revise the training/validation plan; keep every already-inspected test marked as such; reserve fresh whole captures and device sessions for the next final test. Include benign high-volume and interactive traffic as well as multiple attack families. Set operational acceptance gates before reading final results. Only evaluate early-warning claims after a current-window detector qualifies.

## Measured diagnostic results

| Model | Validation recall | Inspected test recall | Inspected test FPR | Inspected supplementary recall |
|---|---:|---:|---:|---:|
| logistic | 1.12% | 100.00% | 34.73% | 87.11% |
| random_forest | 99.70% | 0.00% | 26.04% | 56.90% |

The inspected test has only three malicious windows and 2,865 negatives. The supplementary capture has 1,195 malicious windows and only four negatives. Neither split alone establishes balanced detection quality. No detector was deployed.
