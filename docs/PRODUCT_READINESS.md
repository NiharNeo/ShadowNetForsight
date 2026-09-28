# Product readiness — 25 September 2026

## Latest update — 27 September 2026

The packet-aligned IoT-23 candidate has been trained and independently tested; it has **not** been deployed. Its validation F1 was 97.83%, but the supplementary attack capture produced only 6.58% next-window raw recall, 60.84% OOD rejection and 3.46% accepted detections across all positive targets. The baseline attained 87.43% recall there but previously produced 34.82% false positives on negative test targets. Neither model qualifies for promotion. See [current model evidence](IOT23_MODEL_PILOT.md) for provenance, denominators and reproducible commands.

The immediate model priority is broader reviewed captures and a qualified current-window detector, followed by fresh held-out forecasting tests. Historical statements below about retraining being deferred or real public captures being absent are superseded by this update. The broader 30-session representative lab plan remains incomplete. The live Docker configuration still references the original CIC checkpoint; operational alerts remain disabled.


The local capture-analysis application is operational. Attack-prediction production readiness is blocked by feature compatibility and independent validation, not by dashboard polish.

## Delivered

- Authenticated PCAP/PCAPNG upload and bounded replay in Docker.
- Observed signal stream, network connections, feature attributions and exploratory forecasts.
- Pause/resume and 1×/5×/10×/20× replay controls; one advance request in flight at a time.
- Filter the six displayed leading connections by source/destination address.
- Export JSON with capture/checkpoint SHA-256, actual received windows, forecasts, compatibility status and completion status. Reports retain the latest 720 updates and explicitly count omitted updates; they are not full-history archives for longer captures.
- Explicit extraction compatibility guard. Legacy CSV checkpoint scores cannot generate shadow alerts in PCAP replay, even if OOD calibration accepts them.
- Packet-dataset manifests and newly trained checkpoints carry their extraction contract. Tests compare offline extraction against streamed extraction with reverse packets, gaps and exact window boundaries.
- Future CSV sequence construction rejects histories/targets spanning missing time windows. Single-source chronological splits purge overlapping history/target windows at partition boundaries.

## Measured limitations

`release-evidence/feature-alignment.json` documents why completed-flow CSV features are not equivalent to packet-window features. Existing datasets and checkpoint weights have not been silently rewritten or relabelled. Existing published metrics are legacy results; retraining and reevaluation are required after the sequence fix.

A fresh logistic baseline on the original fixed CSV split achieved 5.31% F1, 4.32% recall and 2.77% false-positive rate. This does not justify replacing the deployed model. These are CSV results, not PCAP validation.

The supplied synthetic fixtures both execute to completion but are outside the model distribution. They remain pipeline fixtures only.

## Required to unblock a detector release

Provide independently collected PCAP sessions with trustworthy attack/benign labels, start/end timestamps, capture hashes and provenance. Use the existing `datasets/pcap_training_plan.example.json` structure for separate train, validation and untouched test partitions. Do not copy one capture into multiple partitions or fit profiles against final demo/test captures.

Build with `pipeline.build_pcap_dataset`, train a candidate using `pipeline.train_lstm`, compare against `pipeline.train_baseline`, and evaluate untouched test sessions. Publish benign false-positive counts, attack misses, rejection coverage and early-warning coverage. Matching feature contracts is necessary but does not certify performance.

Remote deployment, TLS/identity integration, real-broker load validation and an independent security review also remain outside the verified local release scope.


## 26 September — observed evidence and replay reliability

The analysis view now shows protocol packet shares, captured byte totals, observed hosts and TCP SYN-without-ACK counts. All of these use the latest 10,000 processed IP packets, including captured link-layer bytes when present. They are observations, not attack labels. ICMP/ICMPv6 no longer contribute a fabricated port zero to the observed destination-port count; trained model input extraction has not been changed.

Paused replays send an authenticated heartbeat every 20 seconds to avoid the 60-second WebSocket idle timeout without consuming packets. Revocation is checked for heartbeats as well as advance requests. Interrupted exports carry an explicit interrupted status; stopped, paused, running and complete sessions are distinguished.

Validation: 86 automated tests pass, including mixed-protocol byte accounting, bounded summary eviction, heartbeat position preservation and revoked-token rejection. Docker authenticated replay verification passes for both fixture files.


## 26 September — capture-level evaluation workflow

Model evidence now accepts an exported replay and hash-matched labelled timeline, or evaluates the current replay. It reports per-horizon confusion counts, raw and accepted-only metrics, rejection coverage and excluded target windows. A CLI produces the same result. See CAPTURE_EVALUATION.md. This evaluates supplied artifacts; it does not authenticate their labels or prove independent validation.

94 automated tests pass. Synthetic fixture evaluations show the raw +5s classifier flags all 24 scored benign windows and all 24 scored attack windows. Both are entirely rejected. The apparent 100% attack-fixture recall is not evidence of discrimination; the benign fixture has 100% raw false positives. No detector release is approved.
