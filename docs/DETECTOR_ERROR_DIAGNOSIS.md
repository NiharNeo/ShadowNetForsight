# Detector error diagnosis and causal context

Update, 28 September: the context component has now been trained and diagnostically evaluated. It did not reduce the false-positive problem and remains undeployed. See [results](CONTEXT_DETECTOR.md). Statements below describe the earlier implementation stage.

## What was checked

The 25 false-positive windows from the frozen expanded detector were traced back to the original publisher-labelled flows. All 360 packets matched benign labels. No malicious matches appeared when timestamp tolerance was widened from one microsecond to one millisecond for diagnosis. Labels were not rewritten. This rules out that specific timestamp-rounding explanation; it does not independently certify the publisher's labels.

Most errors consist of sparse TCP SYN packets to port 80. Crucially, **18 of the 25 false-positive windows exactly match malicious-labelled training inputs across all 31 float32 current-window features**. A representative benign single-SYN vector matches 228 malicious training anchors. The collision report records the original training archive hash, counts and matching capture IDs. No distance tolerance or approximate match was used.

Under the supplied labels, a deterministic classifier using only this vector cannot distinguish those benign and malicious windows. Threshold tuning or simply increasing model complexity cannot resolve an exact feature collision. Additional causal history or other trustworthy observations are needed.

## Ablation performed

A separate fixed random forest was trained without `ttl_mean`, `ttl_variance` and `tcp_window_mean`, retaining the same training/validation captures and model settings. Its threshold was selected on validation only. This was motivated by observed test errors, so the reused test is explicitly diagnostic, not fresh independent evidence.

| Inspected test | Full-feature v2 | Without the three device-related features |
|---|---:|---:|
| Detected malicious windows | 1,326 | 1,018 |
| Missed malicious windows | 0 | 308 |
| Raw recall | 100% | 76.77% |
| False positives | 25 | 21 |
| Mirai-session false-positive rate | 22.94% | 19.27% |

The ablation does not qualify as a replacement. A drop in false positives at the cost of 308 misses is not an acceptable fix. Feature impurity importance is not causal proof, and exact collisions show that the issue is not solely the three removed features.

## Implemented next input component

`pipeline/connection_context.py` defines a separate `shadownet.connection-context.v1` component with nine features over the recent 60 seconds: packet count, destination endpoints, source hosts, SYN attempts, SYN destinations, SYN connection keys, repeated-SYN fraction, maximum destination share and observed history duration.

It uses one instance per capture, bounded memory, chronological timestamps and past packets only. SYN-ACK replies do not count as new attempts. Exceeding the packet bound invalidates the context and stops scoring rather than silently truncating it. The PCAP adapter emits snapshots before consuming packets from the next window and excludes the final partial window. Its trailing interval is documented as `(t-60,t]`; output-boundary packets belong to the following packet window.

On the inspected false-positive windows, the new context exposes repeated SYN attempts concentrated on a single destination. The first representative single-SYN window has four recent SYN attempts to one connection key, a repeated-SYN fraction of 75% and one SYN destination. These observations are not classifications or proof of benignness; malicious traffic can also repeat one destination.

This component has **not** been incorporated into a trained candidate or deployed. The existing feature contract, live checkpoint and historical evaluation outputs remain intact. Train a separate context-aware candidate, use validation for model selection, and reserve fresh sessions for the next independent test. Also examine remaining extractor semantics before retraining: the legacy `retransmission_count` counts repeated sequence numbers, which can include pure ACKs, and should not be presented as validated TCP retransmission detection. Any correction requires an explicit extraction version and retraining.

## Reproduce and inspect

```sh
.venv-enterprise/bin/python -m scripts.diagnose_detector
.venv-enterprise/bin/python -m scripts.ablate_device_features
.venv-enterprise/bin/python -m unittest discover -s tests
```

Evidence in `docs/release-evidence/`:

- `expanded-detector-v2-flow-audit.json`: per-window packet/flow-label trace.
- `current-window-feature-collisions.json`: exact training/test feature collisions.
- `device-feature-ablation.json`: full diagnostic ablation metrics and artifact hash.
- `error-connection-context.json`: causal context for the inspected error windows.

No model was promoted and no operational alerting was enabled.

Validation: 114 automated tests passed, including chronological context, capture isolation, boundary exclusion and fail-closed overflow.
