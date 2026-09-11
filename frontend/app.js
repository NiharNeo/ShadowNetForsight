let session;
let step = 0;
let timer;
let selectedAction = "close_port";
let liveSocket;
let liveTimer;
let accessToken = sessionStorage.getItem("shadownetToken") || "";

const $ = (id) => document.getElementById(id);

function setSituationBrief(status, headline, what, why, action, tone = "normal") {
  $("briefStatus").textContent = status;
  $("briefStatus").className = `brief-status ${tone}`;
  $("briefHeadline").textContent = headline;
  $("briefWhat").textContent = what;
  $("briefWhy").textContent = why;
  $("briefAction").textContent = action;
}

const demoBriefs = [
  ["NORMAL", "The network looks normal right now.", "Traffic volume and connection behaviour match the expected baseline.", "There is no strong sign of an attack in the current scenario.", "Keep monitoring. No defensive action is recommended yet.", "normal"],
  ["WATCH", "One device may be scanning the network.", "An outside source is contacting many services that it has not used before.", "Scanning often happens before an attacker chooses a service to target.", "Check whether the source is approved. Block it if the activity is unauthorized.", "watch"],
  ["SUSPICIOUS", "Repeated SSH login attempts are forming a pattern.", "The same source is trying several usernames and connections in a short period.", "This behaviour may be an attempt to discover or guess a working account.", "Review the login records and protect the targeted account and host.", "watch"],
  ["HIGH RISK", "The model expects an SSH access attempt soon.", "The sequence now resembles traffic that previously led to initial access.", "A successful login could give the attacker control of the exposed host.", "Verify the alert immediately. Consider restricting SSH and isolating the target.", "danger"],
  ["CRITICAL", "The attacker may move from the first host toward an internal system.", "Credential reuse and internal connections point toward another host.", "Lateral movement can turn one compromised device into a wider incident.", "Isolate the affected hosts, disable exposed credentials, and investigate internal connections.", "danger"],
];

async function login() {
  const username = window.prompt("ShadowNet username");
  if (!username) throw new Error("Authentication cancelled");
  const password = window.prompt("ShadowNet password");
  if (!password) throw new Error("Authentication cancelled");
  const response = await fetch("/api/auth/login", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username, password})});
  if (!response.ok) throw new Error("Authentication failed");
  const result = await response.json();
  accessToken = result.access_token;
  sessionStorage.setItem("shadownetToken", accessToken);
}

async function authenticatedFetch(url, options = {}) {
  if (!accessToken) await login();
  options.headers = new Headers(options.headers || {});
  options.headers.set("Authorization", `Bearer ${accessToken}`);
  let response = await fetch(url, options);
  if (response.status === 401) {
    sessionStorage.removeItem("shadownetToken");
    accessToken = "";
    await login();
    options.headers.set("Authorization", `Bearer ${accessToken}`);
    response = await fetch(url, options);
  }
  return response;
}

async function boot() {
  const results = await Promise.all([
    fetch("/api/session").then((response) => response.json()),
    loadEvidence(),
    loadCalibrationProfiles(),
    loadLabPlan(),
  ]);
  session = results[0];
  $("source").textContent = session.source;
  renderForecast();
  renderPath();
  renderTimeline();
  renderState();
}

async function loadLabPlan() {
  const plan = await fetch("/api/lab-plan").then((response) => response.json());
  const totalSessions = plan.scenarios.reduce((sum, item) => sum + item.sessions, 0);
  const totalMinutes = totalSessions * plan.minimum_capture_minutes;
  $("labStatus").textContent = `${plan.status.toUpperCase()} · ${totalSessions} SESSIONS`;
  $("labStats").innerHTML = `<div><strong>${totalSessions}</strong><span>labelled sessions</span></div><div><strong>${Math.floor(totalMinutes / 60)}h ${totalMinutes % 60}m</strong><span>minimum traffic</span></div><div><strong>${plan.window_seconds}s</strong><span>model windows</span></div>`;
  $("splitBar").innerHTML = plan.partitions.map((item, index) => `<div class="split-${index}" style="width:${item.percent}%"><b>${item.percent}%</b></div>`).join("");
  $("splitLegend").innerHTML = plan.partitions.map((item, index) => `<span><i class="split-${index}"></i>${item.name} · ${item.sessions} sessions</span>`).join("");
  $("scenarioMix").innerHTML = plan.scenarios.map((item) => `<div class="scenario-row"><div><b>${item.name}</b><span>${item.family}</span></div><div class="scenario-count ${item.color}">${item.sessions}</div><p>${item.description}</p></div>`).join("");
  $("labGates").innerHTML = plan.gates.map((gate) => `<li>${gate}</li>`).join("");
}

async function loadCalibrationProfiles(preferred = "") {
  const profiles = await fetch("/api/calibration/profiles").then((response) => response.json());
  const select = $("calibrationProfile");
  const current = preferred || select.value;
  select.innerHTML = '<option value="">Global model (no local profile)</option>' + profiles.map((profile) => `<option value="${profile.domain}">${profile.domain} · ${profile.sample_count} sequences${profile.validation_macro_f1 == null ? "" : ` · ${(profile.validation_macro_f1 * 100).toFixed(1)}% validation F1`}</option>`).join("");
  if ([...select.options].some((option) => option.value === current)) select.value = current;
  renderCalibrationSelection();
}

function renderCalibrationSelection() {
  const domain = $("calibrationProfile").value;
  $("calibrationStatus").textContent = domain ? `Local profile “${domain}” will calibrate probabilities, thresholds and OOD boundaries for the next PCAP upload.` : "No local profile selected. Unknown networks remain protected by global OOD rejection.";
}

async function fitCalibration() {
  const button = $("fitCalibration");
  const domain = $("calibrationName").value.trim().toLowerCase();
  const benign = [...$("benignPcaps").files];
  const attack = [...$("attackPcaps").files];
  if (!domain || !benign.length || !attack.length) throw new Error("Enter a profile name and select both benign and attack PCAPs");
  const body = new FormData();
  body.append("domain", domain);
  benign.forEach((file) => body.append("benign_files", file));
  attack.forEach((file) => body.append("attack_files", file));
  button.disabled = true;
  button.textContent = "Fitting validation profile…";
  $("calibrationStatus").textContent = "Reading labelled captures and fitting local probability, threshold and OOD parameters.";
  try {
    const response = await authenticatedFetch("/api/calibration/profiles", {method: "POST", body});
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Calibration failed");
    await loadCalibrationProfiles(result.domain);
    $("calibrationStatus").textContent = `Profile “${result.domain}” ready: ${result.sample_count} sequences, ${(result.validation_macro_f1 * 100).toFixed(1)}% validation F1. Test it with a separate untouched PCAP.`;
    $("calibrationName").value = "";
    $("benignPcaps").value = "";
    $("attackPcaps").value = "";
  } finally {
    button.disabled = false;
    button.textContent = "Fit calibration profile";
  }
}

async function loadEvidence() {
  const evidence = await fetch("/api/evidence").then((response) => response.json());
  $("claimBadge").textContent = evidence.claims_allowed ? "CLAIMS VERIFIED" : "CLAIMS RESTRICTED";
  $("evidenceMetrics").innerHTML = evidence.horizons.map((item) => `<div class="evidence-stat"><span>+${item.step * 5}s HORIZON</span><strong>${(item.f1 * 100).toFixed(1)}<small> F1</small></strong><p>${(item.false_positive_rate * 100).toFixed(1)}% false positives · ${(item.recall * 100).toFixed(1)}% recall</p></div>`).join("");
  const warning = evidence.early_warning;
  $("leadEvidence").textContent = `${warning.median_lead_seconds ?? 0}s median lead`;
  $("onsetEvidence").textContent = `${warning.onsets_forecast_early} of ${warning.attack_onsets} attack onsets forecast early on the fixed test day.`;
  const worstFpr = evidence.cross_dataset.maximum_false_positive_rate;
  $("crossWarning").textContent = `${(worstFpr * 100).toFixed(0)}% CTU-13 FALSE POSITIVES`;
  $("crossDetail").textContent = `${(evidence.cross_dataset.ood_flag_rate * 100).toFixed(0)}% detected as out-of-distribution and suppressed. The classifier still fails, so deployment claims remain disabled.`;
  $("qualityChart").innerHTML = evidence.horizons.map((item) => `<div class="quality-group"><span>+${item.step * 5}s</span><div><i class="f1" style="height:${Math.max(3, item.f1 * 900)}px" title="F1 ${(item.f1 * 100).toFixed(1)}%"></i><i class="recall" style="height:${Math.max(3, item.recall * 900)}px" title="Recall ${(item.recall * 100).toFixed(1)}%"></i></div></div>`).join("") + '<div class="quality-key"><span><i class="f1"></i>F1</span><span><i class="recall"></i>Recall</span></div>';
  const cicRate = evidence.ood.cic_test_flag_rate * 100;
  const ctuRate = evidence.cross_dataset.ood_flag_rate * 100;
  $("oodChart").innerHTML = `<div class="ood-row"><span>Known CIC test</span><div><i style="width:${cicRate}%"></i></div><b>${cicRate.toFixed(1)}%</b></div><div class="ood-row danger"><span>External CTU-13</span><div><i style="width:${ctuRate}%"></i></div><b>${ctuRate.toFixed(0)}%</b></div><p>High external rejection prevents an untrusted probability from becoming an alert.</p>`;
  const coverage = warning.attack_onsets ? warning.onsets_forecast_early / warning.attack_onsets * 100 : 0;
  $("onsetCoverage").innerHTML = `<div class="coverage-ring" style="--coverage:${coverage}"><strong>${coverage.toFixed(1)}%</strong><span>forecast early</span></div><p><b>${warning.onsets_forecast_early}</b> early forecasts<br>from ${warning.attack_onsets} attack onsets</p>`;
}

function renderForecast() {
  $("forecastChart").innerHTML = session.forecast.map((point) => {
    const uncertainty = Math.max(point.risk - point.low, point.high - point.risk) * 1.1;
    return `<div class="bar-column"><b>${point.risk}%</b><div class="bar" style="height:${point.risk * 1.85}px;--uncertainty:${uncertainty}"></div><small>${point.offset}</small><small>${point.stage}</small></div>`;
  }).join("");
}

function renderPath() {
  $("attackPath").innerHTML = session.path.map((node, index) => {
    const initials = node.id === "attacker" ? "EXT" : node.id.toUpperCase();
    const edgeClass = index === session.path.length - 1 ? "" : `<div class="edge ${index >= 2 ? "predicted" : ""}"></div>`;
    return `<div class="node ${node.kind}"><div class="node-icon"><span>${initials}</span></div><label>${node.label}</label></div>${edgeClass}`;
  }).join("");
}

function renderTimeline() {
  $("timeline").innerHTML = session.stages.map((stage, index) => `<div class="event ${index <= step ? "active" : ""}"><i class="event-dot"></i><time>+${String(index * 20).padStart(2, "0")} SEC</time><div><b>${stage.event}</b><p>${stage.detail}</p></div></div>`).join("");
}

function renderState() {
  const state = session.stages[step];
  $("riskValue").textContent = String(state.risk).padStart(2, "0");
  $("riskRing").parentElement.style.background = `conic-gradient(var(--lime) ${state.risk}%, #21312c 0)`;
  $("riskText").textContent = state.event;
  $("nextStage").textContent = state.name.toUpperCase();
  $("eta").textContent = state.eta;
  $("targetHost").textContent = state.host;
  $("confidence").textContent = `${state.confidence}%`;
  $("riskTrend").textContent = step === 0 ? "● STABLE" : "● RISING";
  $("explanation").textContent = state.detail;
  $("features").innerHTML = state.features.map(([name, value]) => `<div class="feature"><span>${name}</span><div class="track"><div class="fill" style="width:${value}%"></div></div><b>${value}</b></div>`).join("");
  setSituationBrief(...demoBriefs[step]);
  renderTimeline();
}

function startReplay() {
  clearInterval(timer);
  clearInterval(liveTimer);
  if (liveSocket) liveSocket.close();
  if (step >= session.stages.length - 1) {
    step = 0;
    renderState();
  }
  $("play").innerHTML = "<span>Ⅱ</span> Replay running";
  timer = setInterval(() => {
    if (step >= session.stages.length - 1) {
      clearInterval(timer);
      $("play").innerHTML = "<span>↻</span> Replay scripted demo";
      return;
    }
    step += 1;
    renderState();
  }, 1700);
}

function resetReplay() {
  clearInterval(timer);
  clearInterval(liveTimer);
  if (liveSocket) liveSocket.close();
  step = 0;
  $("play").innerHTML = "<span>▶</span> Run scripted attack demo";
  renderState();
}

async function uploadPcap(file) {
  clearInterval(timer);
  clearInterval(liveTimer);
  step = 0;
  $("modelStatus").textContent = "UPLOADING CAPTURE…";
  $("riskValue").textContent = "--";
  $("riskRing").parentElement.style.background = "conic-gradient(var(--lime) 0%, #21312c 0)";
  $("riskText").textContent = "Waiting for 60 seconds of capture history";
  $("riskTrend").textContent = "● WARMING UP";
  setSituationBrief("LEARNING", "The model is reading the capture.", "It is collecting the traffic history needed to make a sequence-based forecast.", "A prediction made before enough history is available would be unreliable.", "Wait for the capture to reach 12 usable five-second windows.", "unknown");
  const body = new FormData();
  body.append("file", file);
  const domain = $("calibrationProfile").value;
  const query = new URLSearchParams({window_seconds: "5"});
  if (domain) query.set("calibration_domain", domain);
  const response = await authenticatedFetch(`/api/replays?${query}`, {method: "POST", body});
  if (!response.ok) throw new Error((await response.json()).detail || "Upload failed");
  const replay = await response.json();
  $("source").textContent = `${replay.filename} · ${(replay.size_bytes / 1024).toFixed(1)} KB · profile: ${replay.calibration_domain}`;
  connectReplay(replay.replay_id);
}

function connectReplay(replayId) {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  liveSocket = new WebSocket(`${protocol}://${location.host}/ws/replays/${replayId}`);
  liveSocket.addEventListener("open", () => {
    liveSocket.send(JSON.stringify({type: "auth", token: accessToken}));
  });
  liveSocket.addEventListener("message", (event) => {
    const update = JSON.parse(event.data);
    if (update.type === "connected") {
      $("modelStatus").textContent = "MODEL WARMING UP 0 / 12";
      $("modelStatus").classList.add("live-model");
      liveTimer = setInterval(() => {
        if (liveSocket.readyState === WebSocket.OPEN) liveSocket.send(JSON.stringify({seconds: 5}));
      }, 900);
      return;
    }
    if (update.type !== "replay_update") return;
    const inference = update.inference;
    if (!inference.model_ready) {
      $("modelStatus").textContent = `MODEL WARMING UP ${inference.warmup_states} / ${inference.required_states}`;
      $("riskValue").textContent = "--";
      $("riskText").textContent = `Collected ${inference.warmup_states} of ${inference.required_states} five-second windows`;
      setSituationBrief("LEARNING", "The model needs more traffic history.", `It has collected ${inference.warmup_states} of ${inference.required_states} required windows.`, "The temporal model compares a full minute of behaviour, not one isolated packet.", "Keep the replay running until the model becomes ready.", "unknown");
    } else {
      $("modelStatus").textContent = "TRAINED LSTM · LIVE INFERENCE";
      applyLiveForecast(inference.forecast, inference.feature_contributions, inference.explanation_method, inference.uncertainty, inference.temporal_contributions);
    }
    if (update.complete) {
      clearInterval(liveTimer);
      if (!inference.model_ready) {
        $("modelStatus").textContent = "CAPTURE TOO SHORT FOR FORECAST";
        $("modelStatus").classList.remove("live-model");
        $("riskValue").textContent = "--";
        $("riskText").textContent = `Need 60 seconds of usable traffic; received ${inference.warmup_states * 5} seconds`;
        $("riskTrend").textContent = "● NO RESULT";
        setSituationBrief("NO RESULT", "This capture is too short for a reliable forecast.", `Only ${inference.warmup_states * 5} seconds of usable traffic were available.`, "The model requires 60 seconds of history before it can compare behaviour over time.", "Try a longer PCAP with continuous traffic, or combine adjacent capture segments.", "unknown");
      } else {
        $("modelStatus").textContent += " · REPLAY COMPLETE";
      }
    }
  });
  liveSocket.addEventListener("error", () => {
    $("modelStatus").textContent = "LIVE CONNECTION ERROR";
    $("modelStatus").classList.remove("live-model");
    setSituationBrief("CONNECTION ERROR", "The live replay connection stopped.", "The dashboard cannot currently receive new PCAP windows from the server.", "Any risk value still visible may be out of date.", "Check the server connection, then upload the capture again.", "danger");
  });
  liveSocket.addEventListener("close", (event) => {
    if (event.code === 4401) {
      sessionStorage.removeItem("shadownetToken");
      accessToken = "";
      $("modelStatus").textContent = "LOGIN EXPIRED · UPLOAD THE PCAP AGAIN";
      setSituationBrief("LOGIN REQUIRED", "The secure replay session expired.", "The one-hour login token is no longer valid.", "The server rejected the live stream to prevent unauthenticated access.", "Upload the PCAP again and sign in when prompted.", "watch");
    }
  });
}

function applyLiveForecast(forecast, contributions = [], method = "integrated_gradients", uncertainty = null, temporal = []) {
  if (!forecast.length) return;
  const current = forecast[0];
  $("riskValue").textContent = String(Math.round(current.risk)).padStart(2, "0");
  $("riskRing").parentElement.style.background = `conic-gradient(var(--lime) ${current.risk}%, #21312c 0)`;
  $("riskText").textContent = `Live +${current.offset_seconds}s model forecast`;
  $("nextStage").textContent = current.stage.toUpperCase();
  $("confidence").textContent = `${Math.round(current.confidence)}%`;
  $("eta").textContent = `${current.stage} in ~${current.offset_seconds} sec`;
  if (uncertainty?.status === "out_of_distribution") {
    $("modelStatus").textContent = "UNKNOWN NETWORK · ALERTS SUPPRESSED";
    $("modelStatus").classList.remove("live-model");
    $("riskText").textContent = "Traffic is outside the validated training envelope";
    $("eta").textContent = "Analyst review required · no automated alert";
    setSituationBrief("UNKNOWN TRAFFIC", "This traffic does not resemble the model's validated training data.", "The statistical pattern falls outside the network behaviour the model knows.", "The displayed probability may not be trustworthy on this network.", "Review the capture manually and calibrate the model on representative local traffic before using alerts.", "unknown");
  } else if (uncertainty) {
    $("modelStatus").textContent = "CALIBRATED LSTM · IN-DISTRIBUTION";
    const roundedRisk = Math.round(current.risk);
    const tone = current.alert ? "danger" : roundedRisk >= 40 ? "watch" : "normal";
    const status = current.alert ? "ALERT" : roundedRisk >= 40 ? "WATCH" : "LOW RISK";
    setSituationBrief(status, `The model estimates ${roundedRisk}% attack risk in the next ${current.offset_seconds} seconds.`, `The strongest forecast points toward the ${current.stage} stage.`, current.alert ? "The probability crossed the calibrated alert threshold." : "The probability remains below the calibrated alert threshold.", current.alert ? "Review the evidence and affected hosts before choosing a defensive action." : "Continue monitoring and compare the next forecast window.", tone);
  }
  $("forecastChart").innerHTML = forecast.map((point) => {
    const uncertainty = Math.max(point.risk - point.risk_low, point.risk_high - point.risk) * 1.1;
    return `<div class="bar-column"><b>${Math.round(point.risk)}%</b><div class="bar" style="height:${point.risk * 1.85}px;--uncertainty:${uncertainty}"></div><small>+${point.offset_seconds}s</small><small>${point.stage}</small></div>`;
  }).join("");
  if (contributions.length) {
    const peak = temporal.length ? temporal.reduce((best, item) => item.contribution > best.contribution ? item : best) : null;
    $("explanation").textContent = `Integrated feature and time sensitivity for next-window risk${peak ? `; strongest historical contribution at ${peak.history_offset_seconds}s` : ""}.`;
    $("features").innerHTML = contributions.map((item) => `<div class="feature"><span>${item.feature.replaceAll("_", " ")}</span><div class="track"><div class="fill" style="width:${item.contribution}%"></div></div><b>${item.contribution.toFixed(1)}%</b></div>`).join("");
    $("explainMethod").textContent = `${method.replaceAll("_", " ")} · 24 integration steps from the training-mean baseline · association, not causation.`;
  }
}

async function simulate() {
  const button = $("simulate");
  button.textContent = "Simulating future states…";
  const response = await authenticatedFetch("/api/simulate", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({action: selectedAction})});
  if (!response.ok) throw new Error((await response.json()).detail || "Simulation failed");
  const outcome = await response.json();
  $("beforeRisk").textContent = `${outcome.before}%`;
  $("afterRisk").textContent = `${outcome.after}%`;
  $("delta").textContent = `−${outcome.reduction} pts projected risk`;
  $("simExplanation").textContent = `${outcome.explanation} ${outcome.disclaimer} Method: ${outcome.method.replaceAll("_", " ")}.`;
  button.textContent = "Run simulation";
}

$("play").addEventListener("click", startReplay);
$("reset").addEventListener("click", resetReplay);
$("simulate").addEventListener("click", simulate);
$("uploadPcap").addEventListener("click", () => $("pcapFile").click());
$("pcapFile").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) uploadPcap(file).catch((error) => {
    $("modelStatus").textContent = error.message.toUpperCase();
    setSituationBrief("UPLOAD FAILED", "The capture could not be analysed.", error.message, "No new model result was produced.", "Correct the reported problem and upload the PCAP again.", "danger");
  });
  event.target.value = "";
});
$("calibrationProfile").addEventListener("change", renderCalibrationSelection);
$("fitCalibration").addEventListener("click", () => fitCalibration().catch((error) => { $("calibrationStatus").textContent = error.message; }));
$("actions").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  selectedAction = button.dataset.action;
  document.querySelectorAll("#actions button").forEach((item) => item.classList.toggle("selected", item === button));
});

boot().catch((error) => {
  $("source").textContent = `API unavailable: ${error.message}`;
});
