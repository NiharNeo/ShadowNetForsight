# ShadowNet ForeSight — current status

## Latest — 28 September: context candidate trained

The 40-feature context-aware detector was trained and evaluated on the existing inspected test. It retained 100% raw recall but produced 28 false positives versus v2's 25. Mirai-session FPR remained 22.94%. It was not promoted. Next priority is a versioned data revision with reviewed benign Linux/TCP behaviour and new independent test sessions. See [context experiment](CONTEXT_DETECTOR.md). Latest regression suite: 115 passing tests.

## Latest diagnosis and implementation

18 of the 25 expanded-detector false positives exactly collide with malicious-labelled training vectors. A device-feature ablation reduced false positives only slightly while introducing 308 misses, so it was not promoted. A bounded causal connection-context component is implemented and tested, but not trained or deployed. See [diagnosis and next input component](DETECTOR_ERROR_DIAGNOSIS.md). Latest regression suite: 114 tests pass.

## Expanded training and fresh test — latest result

Added two training captures and two fresh test captures. Validation selected a random-forest current-window detector; on the new test it detected 1,326/1,326 malicious windows and produced 25 false positives. Aggregate FPR was 1.62%, but FPR within the Mirai capture was 22.94%, exceeding the predeclared 5% per-capture budget. Research screening failed; the candidate was not deployed. The test is now inspected. See [full expanded experiment](EXPANDED_DETECTOR_V2.md). 107 automated tests pass.

## Current-window detector follow-up

Two offline current-window detectors are implemented, trained and evaluated without future-window inputs or warm-up. Neither qualifies for promotion. See [detector results](CURRENT_DETECTOR.md). The latest regression suite passes 105 tests. The next priority remains broader representative data and fresh held-out evaluation.

## Latest update — 27 September 2026

The packet-aligned IoT-23 candidate has been trained and independently tested; it has **not** been deployed. Its validation F1 was 97.83%, but the supplementary attack capture produced only 6.58% next-window raw recall, 60.84% OOD rejection and 3.46% accepted detections across all positive targets. The baseline attained 87.43% recall there but previously produced 34.82% false positives on negative test targets. Neither model qualifies for promotion. See [current model evidence](IOT23_MODEL_PILOT.md) for provenance, denominators and reproducible commands.

The immediate model priority is broader reviewed captures and a qualified current-window detector, followed by fresh held-out forecasting tests. Historical statements below about retraining being deferred or real public captures being absent are superseded by this update. The broader 30-session representative lab plan remains incomplete. The live Docker configuration still references the original CIC checkpoint; operational alerts remain disabled.


Assessment: **local Docker demo verified; not approved for operational attack alerting.**

Immediate priority: submit a working demo video within two days. Enterprise
rollout and model retraining are deferred. See `DEMO_VIDEO_RUNBOOK.md`.
Team TECHTREK · Team ID 140638

## Implemented and locally verified

- PCAP replay and telemetry ingestion through the trained model, with bounded sessions and input checks.
- Password authentication, role checks, token revocation, persistent login limits and keyed audit history.
- Shadow-only forecast contract; experimental threshold crossings cannot issue operational alerts.
- Checkpoint fingerprint verification and validation of calibration provenance and numerical parameters.
- Consistent telemetry/host evidence, late-event rejection and Kafka worker failure visibility.
- Deployment-owned Kafka TLS, mutual TLS and SASL_SSL settings; verified using consumer doubles.
- Authenticated backup/restore snapshots; production-mode startup from restored accounts and audit history.
- Request correlation, redacted errors, security headers and readiness checks.
- Python 3.12 environment, pinned dependencies, container configuration and CI workflow.

## Evidence and its limits

The latest local test count is recorded in `release-evidence/summary.json`.
The production-mode smoke checks cover startup, authentication, trained inference,
telemetry, restore and revocation on macOS. The synthetic 30-second inference
exercise completed 790 predictions with four callers; p95 was 156.65 ms. This is
not a real-traffic throughput or endurance certification.

The recorded Python dependency audit found zero known vulnerabilities across 40
packages on 24 September 2026. This does not cover the container image or prove
absence of vulnerabilities. Docker Desktop is installed. The Linux/arm64 image was built and the localhost
Compose deployment passed authenticated HTTP/WebSocket replay before and after
restart. Dashboard rendering and scripted playback/reset were checked in-browser.
Remote CI has not been executed during this work. Changes remain local and uncommitted.

## Main blocker: detection quality

The recorded CIC test results show recall of 3.7%, 6.7% and 5.3% across the three
forecast horizons, with F1 of 5.2%, 7.5% and 6.1%. Only 14 of 215 attack onsets
were forecast early (6.5% coverage). The reported 15-second median lead applies
only to those successful early warnings, not all attacks.

On the small CTU-13 evaluation (28 sequences), the raw classifier's maximum
false-positive rate was 100%; OOD rejection suppressed all sequences. This is
not successful cross-network detection. Mitigation results remain illustrative
simulations, not demonstrated causal interventions.

## Work required to move forward

1. Acquire independently collected, authorized representative captures with reviewed
   timelines: at least 18 training, 6 validation and 6 untouched test sessions.
   `datasets/pcap_training_plan.json` is currently absent. Synthetic fixture captures
   do not meet this evidence requirement. The workflow rejects reused paths and
   byte-identical captures, even after renaming; hashes alone cannot establish true
   session independence or detect overlapping capture segments.
2. Retrain and compare against the baseline. Agree acceptance targets for onset
   coverage, false alerts per hour and lead time before inspecting held-out results.
3. Run remote CI, real Kafka TLS/authentication/redelivery checks, and
   sustained workload tests on the target hardware.
4. Validate target-host TLS, encrypted storage, restore, monitoring, access controls,
   centralized identity/audit and independent security review.

Engineering hardening has progressed substantially. Model validation is the
critical path; further infrastructure changes alone will not make forecasts
production-ready or guarantee an SIH result.
