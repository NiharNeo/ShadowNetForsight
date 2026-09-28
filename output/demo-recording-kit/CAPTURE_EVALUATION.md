# Evaluate a capture against ground truth

Open **Model evidence → Compare forecasts with ground truth**. Choose a labelled timeline JSON and click **Evaluate capture**. Leave the analysis-export field empty to use the current replay, or select a previously exported analysis JSON. Sign in as an operator when prompted. Export evaluation saves the complete results and opens a selectable JSON preview.

A timeline is tied to the exact capture bytes:

```json
{
  "sha256": "<64-character lowercase SHA-256 of the PCAP>",
  "duration_seconds": 180,
  "timeline": [
    {"start_seconds": 0, "end_seconds": 90, "label": 0},
    {"start_seconds": 90, "end_seconds": 180, "label": 1}
  ]
}
```

Label 0 means benign; label 1 means attack. The timeline must cover the capture without overlaps or gaps. A capture manifest containing a `captures` list is also supported, with exactly one matching hash. Hash matching prevents accidentally pairing unrelated captures and labels; it does not authenticate either artifact or verify the labels.

At elapsed replay time E, the +5-second forecast targets [E, E+5), +10 targets [E+5, E+10), and +15 targets [E+10, E+15). A window crossing a benign/attack boundary is excluded rather than assigned a misleading label. Forecasts beyond the processed capture history are excluded. Adjacent intervals carrying the same binary label are merged for scoring.

- **Raw classifier:** thresholded exported scores, regardless of OOD rejection.
- **Accepted only:** windows marked in distribution with a matching feature-extraction contract. This is not operational alerting.
- **Rejection rate:** rejected windows divided by scored windows. Rejections are not true negatives or successful detections.
- **N/A:** the metric's denominator has no examples. For example, a capture with no scored benign windows cannot establish false-positive rate.

The evaluator never fits thresholds or modifies the model. Results include label-document, capture and checkpoint fingerprints. Browser reports retain only the latest 720 updates; omitted history is disclosed and cannot be recovered by evaluation. These artifacts remain curator supplied, and evaluation does not certify their independence or authenticity.

## Reproduce from the command line

```sh
.venv-enterprise/bin/python -m pipeline.evaluate_capture \
  --report output/demo-recording-kit/pilot-attack-3m-analysis.json \
  --labels data/demo/captures/pilot-manifest.json \
  --output output/capture-evaluation.json
```

Run `.venv-enterprise/bin/python -m scripts.audit_demo_captures` to regenerate both fixture analysis exports and evaluations. The synthetic pilot is a workflow test, not detector-performance evidence. Its attack begins at the model warm-up boundary, so the scored attack fixture contains no benign future windows and cannot establish benign false-positive performance by itself.
