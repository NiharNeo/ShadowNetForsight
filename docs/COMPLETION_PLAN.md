# Completion plan and planning estimates

## Latest update — 27 September 2026

The packet-aligned IoT-23 candidate has been trained and independently tested; it has **not** been deployed. Its validation F1 was 97.83%, but the supplementary attack capture produced only 6.58% next-window raw recall, 60.84% OOD rejection and 3.46% accepted detections across all positive targets. The baseline attained 87.43% recall there but previously produced 34.82% false positives on negative test targets. Neither model qualifies for promotion. See [current model evidence](IOT23_MODEL_PILOT.md) for provenance, denominators and reproducible commands.

The immediate model priority is broader reviewed captures and a qualified current-window detector, followed by fresh held-out forecasting tests. Historical statements below about retraining being deferred or real public captures being absent are superseded by this update. The broader 30-session representative lab plan remains incomplete. The live Docker configuration still references the original CIC checkpoint; operational alerts remain disabled.


**Updated priority:** a demo video is due in two days. The Docker demo is now
built and verified locally; use `DEMO_VIDEO_RUNBOOK.md` for rehearsal and recording.
The enterprise estimates below are deferred planning, not the current deadline.

These are conditional planning ranges, not guaranteed completion dates. They
assume 3–4 focused teammates, an available authorized isolated lab and suitable
compute within two working days, and no major scope expansion. The actual SIH
deadline and team availability still need to be confirmed.

| Deliverable | Estimated time from now | Meaning of completion |
|---|---:|---|
| Rehearsed SIH prototype demo | 2–4 working days | Repeatable authenticated demo, working trained inference, recovery and honest evidence; detection claims remain restricted |
| Evaluated SIH model iteration | 2–3 weeks | Representative captures, reviewed labels, baseline comparison and untouched-test report; improvement is not guaranteed |
| Controlled production pilot | 3–6 weeks | Target-host deployment, real Kafka integration, load/recovery checks and agreed model acceptance gates passed |
| Broader enterprise release | 8–12+ weeks | Pilot acceptance plus identity integration, centralized audit/monitoring, security review and operational ownership |

If the model fails agreed acceptance targets, the pilot and enterprise dates move.
Neither synthetic test success nor a trained checkpoint guarantees useful early
warning. The present scope is one organization and one worker; multi-tenant or
high-availability deployment would require additional architecture and time.

## Critical path

1. Confirm deadline, available team capacity, lab access, deployment target, and
   measurable acceptance targets. Keep scope fixed during the SIH preparation.
2. Collect at least 30 independent sessions: 18 train, 6 validation, 6 untouched
   test. At the planned minimum 15 minutes per session, recording alone totals
   7.5 hours, before lab setup, resets, review, labels and repeat captures. Budget
   3–5 working days for acquisition and provenance/label review with the lab ready.
3. Build the capture dataset, fit baseline and temporal models, and tune only on
   validation data. Budget 3–5 working days for the first iteration; compute time
   and additional iterations depend on observed results.
4. Evaluate once on untouched test sessions against pre-agreed onset coverage,
   false alerts/hour and lead-time targets; allow 1–2 days for analysis and review.
5. In parallel, run Linux/container CI, a real Kafka TLS/SASL test, target-host
   restore and sustained workload tests. Budget 3–5 working days for the initial
   deployment pass, then fix measured failures and rehearse the demo.
6. Run a monitored pilot and complete identity, centralized audit, retention,
   incident response and independent security review before general release.

## Current external constraints

- The real capture training manifest is absent. Existing generated PCAPs are
  pipeline fixtures, not independent empirical validation.
- The configured public archive acquisition preflight estimates 79.8 GB working
  space. The latest local check had 61.8 GB free, approximately 18.0 GB short.
  This is a local capacity estimate, not verification of remote archive availability.
  Public data is an alternative input and does not replace local-network validation.
- Local Linux/arm64 Docker deployment is verified; remote container CI is not yet run.
- No real Kafka broker or target-host deployment has been verified in this work.
- Operational alerts remain disabled because recorded model quality is insufficient.
