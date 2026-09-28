# ShadowNet ForeSight: selection and demo playbook

Prepared 20 September 2026 for TECHTREK, Team ID 140638. This is a competition preparation plan, not a prediction of selection. The PPTX is a six-slide submission draft. Confirm the official current template, upload format, deadline, college and team metadata with your SPOC before uploading. The official portal could not be independently accessed during preparation. Existing project decks supplied the problem title and SIH visual asset.

## The strongest case you can currently defend

ShadowNet ForeSight is a working traffic-to-forecast research prototype with explanations, unfamiliar-traffic checks and an auditable analyst workflow. Its next proof is useful early warning on unseen network sessions under a stated false-alert budget.

The architecture is substantial, but the current forecasting evidence is weak. Only 14 of 215 attack onsets received early warning, approximately 6.5%. A polished deck cannot substitute for improving and validating this result. More dashboard features are a lower priority than representative data and a fair baseline comparison.

## Work in priority order

1. **Freeze the evaluation contract before retraining.** Define attack onset, pre-onset warning eligibility, forecast horizons, alert aggregation, false alerts per monitored hour and how abstentions count. Count missed attacks even when OOD suppresses their alerts. Report both classifier and complete-system results. Select thresholds using validation data only.
2. **Collect the planned 30 isolated sessions.** Use the existing capture plan: 9 normal interactive, 6 benign high-volume, 5 discovery, 5 authentication-pressure and 5 rate-limited web-stress sessions. Keep each complete session in only one partition: 18 training, 6 validation and 6 untouched test. Ensure scenario representation where possible. Record capture hashes, device roles, exact attack onset and label provenance. Synthetic fixture PCAPs remain pipeline tests. Thirty sessions are a first study, not sufficient evidence of broad deployment readiness.
3. **Remove dataset shortcuts.** Inspect whether time of day, endpoint IDs, capture duration or traffic-generation artifacts reveal labels. Include benign bursts that resemble attacks. Audit feature availability at prediction time, especially completed-flow statistics that would not yet exist during live inference. Do not let windows or related attack runs cross partitions.
4. **Demonstrate incremental forecasting value.** Compare a constant/persistence predictor, a static model and the temporal model using identical inputs, splits and alert budgets. Include an ablation without temporal history. Report onset coverage, precision, recall, F1, false alerts/hour, lead-time distribution, calibration and abstention coverage. Use uncertainty intervals appropriate to independent sessions, not a claim of thousands of independent windows. Report attack-family results and failures.
5. **Strengthen the world-model fit deliberately.** The current temporal classifier is a starting point. A research extension could predict future state representations and evaluate multi-step rollout errors. Add action-conditioned transitions only after collecting controlled intervention data and validating their effects. Do not rename the current fixed-probability simulator a learned causal world model.
6. **Freeze a reliable demonstration.** Keep scripted UI demonstrations visibly labelled. Run actual checkpoint inference on replay separately, showing capture ID, model/version, event clock, forecast issue time and later onset. Retain a recording and local files for an offline fallback. Measure inference latency and resource use before claiming real-time readiness.
7. **Package for reproducibility.** Include pinned setup instructions, checkpoint identity, split manifest, evaluation JSON and test report. Keep private capture payloads and secrets out of a public repository. Add a public repository or demo link to the deck only when the team has a reviewed, accessible destination.

Recommended promotion gate: the temporal model must improve pre-onset coverage over the strongest baseline at the same predeclared alert budget on untouched sessions. No numerical accuracy promise is justified yet. If the first evaluation fails, report it and acquire new data rather than repeatedly tuning against the same test set.

## Suggested team ownership

Assign names to these responsibilities: data and lab isolation; feature pipeline and labels; model and evaluation; backend and inference; dashboard and demonstration; submission and judge rehearsal. These are responsibilities, not a claim about current team membership.

## Two-minute pitch

Security analysts can see suspicious activity, but they still need to decide what may happen next and whether a warning deserves attention.

ShadowNet ForeSight explores that decision for SIH problem 26153. We convert traffic into five-second network states and use a temporal model to estimate attack risk at five, ten and fifteen seconds ahead. The analyst sees the forecast together with the features and time windows that influenced it. When traffic falls outside the validated distribution, the system suppresses operational alerts and requests review.

Our prototype already connects ingestion, model inference, explanations and a SOC dashboard. It includes access controls and audit integrity. A scenario simulator lets an analyst explore declared defence assumptions, although it does not prove real-world causal effects.

We also know the main limitation. On the fixed CIC test, we warned early for fourteen of two hundred and fifteen attack onsets. The median lead among those successful warnings was fifteen seconds. Recall is too low for deployment claims. An external diagnostic also exposed a classifier failure, which the unfamiliar-traffic check caught.

Our next milestone is a controlled thirty-session corpus with independent training, validation and untouched test captures. We will compare temporal forecasting with simpler baselines under the same false-alert budget.

The value we aim to demonstrate is useful warning before an attack progresses, with enough evidence and uncertainty information for an analyst to make a defensible decision.

## Three-minute demonstration

- **0:00–0:25:** Identify the capture and checkpoint. Explain whether the view is scripted or uses trained inference.
- **0:25–1:15:** Replay a labelled capture. Show that the issue time precedes the observed onset for a real successful forecast. Also show a missed onset so the limitations are concrete. Do not cherry-pick the success as representative coverage.
- **1:15–1:45:** Open the attribution and Situation Brief. Distinguish model attribution from causal explanation and inferred target context from validated target prediction.
- **1:45–2:10:** Show the OOD response on the documented external diagnostic. Explain that rejection reduces unsafe alerts but may hide attacks.
- **2:10–2:35:** Demonstrate a mitigation scenario with its declared topology and probabilities visible. Describe it as an estimate under assumptions.
- **2:35–3:00:** Open the fixed evaluation report and split manifest. State the next experiment and promotion gate.

A five-second window and a fifteen-second horizon do not automatically provide fifteen usable seconds. Account for ingestion delay, window completion, inference and analyst response time.

## Questions judges are likely to ask

**How is this different from an IDS?**
The task is future-state prediction from a history of observed states. We must demonstrate pre-onset warning, not just classify traffic after malicious activity starts. We do not claim existing security products lack predictive capabilities.

**Why is the accuracy low?**
We have measured low recall and domain shift. Limited representative local data and feature mismatch are hypotheses to investigate, not established explanations. The next study uses consistent capture features, stronger benign controls and independent sessions.

**Is this a world model?**
The implemented model forecasts future risk and proxy stages from temporal context. A learned state-transition model with validated action-conditioned rollouts is future work. The existing simulator uses declared probabilities.

**Does OOD rejection solve false positives?**
It suppressed operational alerts on the tested external sample, but all 28 sequences were rejected. That is an abstention result, not evidence of generalization or reliable attack detection. Coverage and missed attacks must accompany false-alert metrics.

**Are those native MITRE labels?**
No. Current stage labels use documented proxy mappings. Ground-truth attack-stage and target evaluation need separate labels.

**Why only 5–15 seconds?**
Those are the implemented horizons. Whether they support useful action is unproven and depends on pipeline latency and the response workflow. Longer horizons require new evaluation, not extrapolation.

**Why no blockchain?**
The present trust model is within one organization. Capture hashes and keyed audit chains provide tamper evidence under their key-management assumptions. Independent shared attestation could justify a different design later. Neither hashing nor a local chain proves who originally captured data.

**Can it block attacks?**
The current product supports analyst review and simulated actions. We do not claim validated autonomous prevention.

**How do you prevent leakage?**
Independent capture/run partitions, history boundaries, validation-only calibration and a sealed test set. Also audit feature timestamps so the model never uses information unavailable when it issued the forecast.

**What does a successful next result look like?**
Better early-warning coverage than a strong baseline at the same agreed false-alert budget, on untouched sessions, with useful lead time after processing delay. Report confidence and failures alongside the point estimates.

## Submission checks

Confirm the exact official slide template and all required headings with the SPOC. Six slides here are a working assumption based on the existing project material, not verified current portal rules. Verify TECHTREK and Team ID 140638, and add the college name if required. If PDF is required, export the final approved deck and inspect all pages before uploading. Keep the working PPTX editable. Verify every link and record the accepted submission acknowledgement.

Sources for measured results: `models/cic2018-multiday-lstm/evaluation-summary.json`. Simulator scope: `pipeline/mitigation_simulator.py`. Data workflow: `scripts/run_project_workflow.py`. Research foundations: [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html), [Integrated Gradients](https://arxiv.org/abs/1703.01365), [World Models](https://worldmodels.github.io/). These research sources do not validate ShadowNet's results.
