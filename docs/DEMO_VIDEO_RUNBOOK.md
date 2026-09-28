# TECHTREK — two-day demo delivery

The goal is a reliable recorded demonstration of working software. Enterprise
rollout and new model research are deferred. Use a 3–4 minute recording unless
the official submission rules specify a different limit.

## Start the demo

```sh
.venv-enterprise/bin/python scripts/demo.py up
```

Docker Desktop must be running. The command builds the application, starts the
`shadownet-demo` Compose project, waits for readiness, and creates an operator.
Open `http://localhost:8000`. Private credentials are in `data/demo/access.json`;
view them before recording. The persistent demo volume is separate from other
Compose projects. Port 8000 must be free. Do not use `down -v` during rehearsals.

```sh
.venv-enterprise/bin/python scripts/demo.py status
.venv-enterprise/bin/python scripts/demo.py stop
```

Rerunning `up` preserves the account and data. If credentials were independently
changed, use the normal account-management procedure; the launcher does not reset
passwords silently. Keep `.env.demo` and `data/demo/access.json` private.

## Recording sequence

| Time | Screen/action | Narration |
|---|---|---|
| 0:00–0:20 | Dashboard and team introduction | “We are TECHTREK, team 140638. ShadowNet ForeSight explores short-horizon attack forecasting from network traffic.” |
| 0:20–1:10 | Upload `pilot-attack-3m.pcap`; sign in | “This synthetic fixture goes through packet parsing and five-second windows. The signal graph and host connections come from the uploaded packets.” |
| 1:10–1:45 | Show completed replay, forecasts and attributions | “After 60 seconds of capture history, the checkpoint computes three forecast horizons. This capture is outside its training distribution; these are exploratory scores.” |
| 1:45–2:15 | Clear capture, upload `pilot-benign-3m.pcap` | “The benign fixture is also rejected. We are demonstrating pipeline execution, not claiming accurate classification on these fixtures.” |
| 2:15–2:50 | Open Model evidence | “The live model and offline detector studies are shown separately. The latest detector found 1,326 labelled malicious windows, but failed our per-capture false-positive limit and was not deployed.” |
| 2:50–3:15 | Show Docker readiness and the compatibility report | “The report includes file and checkpoint hashes, actual forecasts, and rejection decisions so these results can be reproduced.” |
| 3:15–3:40 | Close with next milestone | “We have trained packet-aligned candidates; per-capture false positives remain the release blocker. Next we will add representative benign traffic and test on fresh sessions.” |

Do not narrate the current model as having high accuracy. Do not present synthetic
traffic as a real attack capture or the scripted sequence as a model prediction.
Historical early-warning figures were superseded by a timing correction; do not
quote the old 15-second lead or onset coverage in the recording. Show OOD suppression as a
working safety mechanism, not as evidence that detection succeeded.

## Schedule

**Day 1:** verify Docker startup, run both capture fixtures, check login and replay
completion in the browser, rehearse the sequence twice, then freeze the demo scope.

**Day 2:** record a clean take and backup take, add voice-over/captions and team ID,
review every claim against the actual screen, check audio and legibility, export
and play the final video, then submit with several hours of margin. Keep the
approved file and a local copy. Do not attempt a major dependency/model upgrade
between rehearsal and recording.

## Before recording

- Confirm official duration, format, resolution and upload limit.
- Start Docker and wait for readiness before opening the recording tool.
- Disable desktop notifications and hide credentials, terminals with secrets and
  unrelated personal windows. Use a clean browser window.
- Run `scripts/demo.py prepare` if the two short capture files are missing.
- Rehearse one complete upload; the 180-second fixture replays in roughly half a
  minute at the current UI rate, plus model warm-up and processing overhead.
- If Docker or the browser fails, resolve it before the take; do not record a
  frozen screen as a live result. Preserve the last verified build.

## Analysis controls

Use Pause replay before explaining a result, then Resume replay. Speed changes the replay pacing while retaining five-second model windows. Hover a signal point to inspect its UTC timestamp and measured packet rate. The host filter searches only the six displayed leading connections. Export analysis JSON provides a download and a selectable preview, with capture/model hashes and actual outputs. Reports retain the latest 720 updates and disclose omitted older updates.


## Final recording freeze — 28 September

Use the current local Docker build and the two three-minute synthetic fixtures. The live checkpoint has not been replaced. New offline detector cards are measured research results, not outputs from the uploaded fixture and not forecasting accuracy. The early-warning panel now withholds superseded lead-time figures.

Sign in before recording. Rehearse once at 20×, then clear the capture without reloading the page so the in-memory login stays available. For the take, upload the attack fixture, let the graph and connections develop, pause to explain, resume, and export the analysis. Show the benign fixture briefly if time permits. Finish in Model evidence with the offline/live distinction and the next validation step. Skip calibration and the illustrative sandbox in the main recording unless requested by the submission brief.

The suggested duration is 3–4 minutes, not a verified official requirement. Confirm the submission portal's actual limit before recording. The video itself has not been recorded or submitted.
