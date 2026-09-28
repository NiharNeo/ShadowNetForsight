let session;
let step = 0;
let timer;
let selectedAction = "close_port";
let liveSocket;
let liveTimer;
let replayHeartbeat;
let accessToken = "";
let replayPaused = false;
let replayPending = false;
let replayComplete = false;
let analysisReport = null;
let lastNetwork = null;
let currentReplayId = null;

function scheduleReplay() {
  clearInterval(liveTimer);
  if (!liveSocket || replayPaused || replayComplete) return;
  liveTimer = setInterval(() => {
    if (!replayPending && liveSocket?.readyState === WebSocket.OPEN) {
      replayPending = true;
      liveSocket.send(JSON.stringify({seconds: 5}));
    }
  }, 5000 / Number($("replaySpeed").value));
}

function clearTrafficEvidence() {
  for (const id of ["observedBytes", "observedHosts", "observedSyn"]) $(id).textContent = "—";
  $("protocolMix").textContent = "Upload a capture to inspect protocols.";
  $("trafficScope").textContent = "Evidence from the latest 10,000 processed IP packets; no attack classification implied.";
}
function renderTrafficEvidence(network) {
  $("observedBytes").textContent = (network.captured_packet_bytes ?? 0).toLocaleString();
  $("observedHosts").textContent = network.host_count.toLocaleString();
  $("observedSyn").textContent = network.syn_requests.toLocaleString();
  $("trafficScope").textContent = `Latest ${network.packets_in_scope.toLocaleString()} processed IP packets (maximum 10,000). Byte counts include captured link-layer headers when present. These observations do not establish an attack.`;
  const container = $("protocolMix"); container.replaceChildren();
  for (const protocol of network.protocols || []) {
    const row = document.createElement("div"); row.className = "protocol-row";
    const label = document.createElement("span"); label.textContent = protocol.name;
    const track = document.createElement("div"); track.className = "protocol-track";
    const bar = document.createElement("i");
    const share = 100 * protocol.packets / Math.max(network.packets_in_scope, 1);
    bar.style.width = `${share}%`; track.append(bar);
    const count = document.createElement("span"); count.textContent = `${protocol.packets.toLocaleString()} · ${share.toFixed(1)}%`;
    row.append(label, track, count); container.append(row);
  }
  if (!container.children.length) container.textContent = "No IP packets processed yet.";
}
function markReplayInterrupted(message) {
  clearInterval(replayHeartbeat);
  clearInterval(liveTimer);
  replayPaused = true;
  replayPending = false;
  $("pauseReplay").disabled = true;
  $("streamStatus").textContent = "INTERRUPTED";
  $("modelStatus").textContent = message;
  $("labReplayDetail").textContent = "Replay interrupted · displayed evidence is from the last received update";
  if (analysisReport) { analysisReport.status = "interrupted"; analysisReport.interruption = message; analysisReport.complete = false; }
}

function exportAnalysis() {
  if (!analysisReport) return;
  showJsonReport({...analysisReport, exported_at: new Date().toISOString()}, "shadownet-analysis.json");
}
function showJsonReport(report, filename) {
  const serialized = JSON.stringify(report, null, 2);
  $("analysisPreview").textContent = serialized;
  $("analysisDialog").showModal();
  const blob = new Blob([serialized], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a"); link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  $("exportStatus").textContent = "Download requested · preview available";
}


function stopLiveReplay() {
  clearInterval(replayHeartbeat);
  clearInterval(liveTimer);
  replayPending = false;
  $("pauseReplay").disabled = true;
  if (analysisReport && !analysisReport.complete) analysisReport.status = "stopped";
  const oldReplayId = currentReplayId;
  currentReplayId = null;
  if (oldReplayId && accessToken) fetch(`/api/replays/${oldReplayId}`, {method: "DELETE", headers: {Authorization: `Bearer ${accessToken}`}}).catch(() => {});
  const previous = liveSocket;
  liveSocket = null;
  if (previous) previous.close();
}

function showScriptedMode() {
  clearTrafficEvidence();
  $("connectionGraph").hidden = true;
  resetSignalGraph();
  $("labReplayStats").textContent = "Scripted scenario";
  $("labReplayDetail").textContent = "Illustration only · corpus collection remains planned";
  $("targetLabel").textContent = "EXPECTED TARGET";
  $("pathTitle").textContent = "Illustrative scenario path";
  $("pathBadge").textContent = "PROXY STAGES";
  $("pathLegend").textContent = "Scripted scenario · illustrative progression";
  $("source").textContent = session.source;
  $("modelStatus").textContent = "SCRIPTED ILLUSTRATION · NOT MODEL INFERENCE";
  $("modelStatus").classList.remove("live-model");
  $("streamStatus").textContent = "SCRIPTED SCENARIO";
  $("forecastLegend").textContent = "Scripted forecast illustration · not trained inference";
  $("explainMethod").textContent = "Scenario evidence is illustrative until a live PCAP replay reaches model readiness.";
  renderForecast();
  renderPath();
}
sessionStorage.removeItem("shadownetToken");

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

let loginPending;
async function login() {
  if (loginPending) return loginPending;
  loginPending = new Promise((resolve, reject) => {
    const dialog = $("loginDialog"), form = $("loginForm");
    const finish = (error) => {
      form.onsubmit = null;
      dialog.oncancel = null;
      $("cancelLogin").onclick = null;
      form.reset();
      dialog.close();
      error ? reject(error) : resolve();
    };
    dialog.oncancel = () => finish(new Error("Authentication cancelled"));
    $("cancelLogin").onclick = () => finish(new Error("Authentication cancelled"));
    form.onsubmit = async (event) => {
      event.preventDefault();
      $("submitLogin").disabled = true;
      try {
        const response = await fetch("/api/auth/login", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username: $("loginUsername").value, password: $("loginPassword").value})});
        if (!response.ok) throw new Error(response.status === 429 ? "Too many attempts. Try again in five minutes." : "Authentication failed");
        const result = await response.json();
        accessToken = result.access_token;
        $("logout").hidden = false;
        finish();
        loadCalibrationProfiles().catch((error) => { $("calibrationStatus").textContent = error.message; });
      } catch (error) {
        $("loginError").textContent = error.message;
      } finally { $("submitLogin").disabled = false; }
    };
    $("loginError").textContent = "";
    dialog.showModal();
  });
  try { return await loginPending; } finally { loginPending = null; }
}

$("logout").addEventListener("click", async () => {
  try {
    const response = await fetch("/api/auth/logout", {method: "POST", headers: {Authorization: `Bearer ${accessToken}`}});
    if (!response.ok && response.status !== 401) throw new Error("Server logout failed. Please retry.");
    accessToken = "";
    stopLiveReplay();
    $("logout").hidden = true;
  } catch (error) { $("modelStatus").textContent = error.message; }
});

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
  resetReplay();
}

async function loadLabPlan() {
  const plan = await fetch("/api/lab-plan").then((response) => response.json());
  const totalSessions = plan.scenarios.reduce((sum, item) => sum + item.sessions, 0);
  const totalMinutes = totalSessions * plan.minimum_capture_minutes;
  $("labStatus").textContent = `${plan.status.toUpperCase()} · ${totalSessions} SESSIONS`;
  $("labStats").innerHTML = `<div><strong>${totalSessions}</strong><span>labelled sessions</span></div><div><strong>${Math.floor(totalMinutes / 60)}h ${totalMinutes % 60}m</strong><span>minimum traffic</span></div><div><strong>${plan.window_seconds}s</strong><span>model windows</span></div>`;
  $("splitBar").innerHTML = plan.partitions.map((item, index) => `<div class="split-${index}" style="width:${item.percent}%"><b>${item.percent}%</b></div>`).join("");
  $("splitLegend").innerHTML = plan.partitions.map((item, index) => `<span><i class="split-${index}"></i>${item.name} · ${item.sessions} sessions</span>`).join("");
  $("scenarioMix").replaceChildren();
  plan.scenarios.forEach((item, index) => {
    const button = document.createElement("button");
    button.className = "scenario-choice";
    button.type = "button";
    button.setAttribute("aria-pressed", "false");
    const title = document.createElement("span"); title.textContent = item.name;
    const count = document.createElement("b"); count.textContent = `${item.sessions} planned`;
    const track = document.createElement("span"); track.className = "scenario-track";
    const fill = document.createElement("i"); fill.style.width = `${item.sessions / totalSessions * 100}%`; track.append(fill);
    button.append(title, count, track);
    button.onclick = () => {
      $("scenarioMix").querySelectorAll("button").forEach(b => b.setAttribute("aria-pressed", String(b === button)));
      $("scenarioDetail").textContent = `${item.family} · ${item.sessions} planned sessions · at least ${item.sessions * plan.minimum_capture_minutes} minutes. ${item.description} These are targets, not collected data.`;
    };
    $("scenarioMix").append(button);
    if(index === 0) button.click();
  });
  $("labGates").innerHTML = plan.gates.map((gate) => `<li>${gate}</li>`).join("");
}

async function loadCalibrationProfiles(preferred = "") {
  if (!accessToken) return;
  const response = await authenticatedFetch("/api/calibration/profiles");
  if (!response.ok) throw new Error("Could not load calibration profiles");
  const profiles = await response.json();
  const select = $("calibrationProfile");
  const current = preferred || select.value;
  select.replaceChildren(new Option("Global model (no local profile)", ""));
  profiles.forEach((profile) => select.add(new Option(`${profile.domain} · ${profile.sample_count} sequences`, profile.domain)));
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
  const studies = evidence.offline_studies;
  if (studies) {
    $("offlineStudies").hidden = false;
    $("studyScope").textContent = studies.scope;
    $("studyDecision").textContent = studies.decision;
    $("studyRows").replaceChildren();
    for (const item of studies.studies) {
      const card = document.createElement("div"); card.className = "evidence-stat";
      const title = document.createElement("span"); title.textContent = item.name;
      const count = document.createElement("strong"); count.textContent = `${item.detected}/${item.positive} detected`;
      const detail = document.createElement("p"); detail.textContent = `${item.false_positives}/${item.negative} negative windows flagged · ${(item.capture_fpr * 100).toFixed(2)}% false positives within the Mirai capture`;
      card.append(title, count, detail); $("studyRows").append(card);
    }
  }
  const warning = evidence.early_warning;
  $("leadEvidence").textContent = "Re-evaluation required";
  $("onsetEvidence").textContent = "Historical lead-time figures were superseded by a timing correction. No verified early-warning lead is claimed for this demo.";
  const worstFpr = evidence.cross_dataset.maximum_false_positive_rate;
  $("crossWarning").textContent = `${(worstFpr * 100).toFixed(0)}% CTU-13 FALSE POSITIVES`;
  $("crossDetail").textContent = `${(evidence.cross_dataset.ood_flag_rate * 100).toFixed(0)}% detected as out-of-distribution and suppressed. The classifier still fails, so deployment claims remain disabled.`;
  $("qualityChart").innerHTML = evidence.horizons.map((item) => `<div class="quality-group"><span>+${item.step * 5}s</span><div><i class="f1" style="height:${Math.max(3, item.f1 * 900)}px" title="F1 ${(item.f1 * 100).toFixed(1)}%"></i><i class="recall" style="height:${Math.max(3, item.recall * 900)}px" title="Recall ${(item.recall * 100).toFixed(1)}%"></i></div></div>`).join("") + '<div class="quality-key"><span><i class="f1"></i>F1</span><span><i class="recall"></i>Recall</span></div>';
  const cicRate = evidence.ood.cic_test_flag_rate * 100;
  const ctuRate = evidence.cross_dataset.ood_flag_rate * 100;
  $("oodChart").innerHTML = [{name:"Known CIC test", rate:cicRate, support:evidence.test_support, color:"var(--cyan)"},{name:"External CTU-13",rate:ctuRate,support:evidence.cross_dataset.support,color:"var(--amber)"}].map(item => `<div class="ood-card"><div class="ood-donut" style="--rate:${item.rate};--tone:${item.color}"><strong>${item.rate.toFixed(1)}%</strong></div><div><b>${item.name}</b><span>${item.support.toLocaleString()} test sequences</span><small>${item.rate.toFixed(1)}% flagged outside distribution</small></div></div>`).join("") + '<p class="ood-note">Flagged traffic is withheld from alerts. 100% external rejection means the model cannot generalize to this sample—not 100% attack detection.</p>';

  $("onsetCoverage").textContent = "Timing methodology corrected · independent first-onset evaluation pending.";
}

function renderForecast() {
  $("forecastChart").innerHTML = session.forecast.map((point) => {
    const uncertainty = Math.max(point.risk - point.low, point.high - point.risk) * 1.1;
    return `<div class="bar-column"><b>${point.risk}%</b><div class="bar" style="height:${point.risk * 1.85}px;--uncertainty:${uncertainty}"></div><small>${point.offset}</small><small>${point.stage}</small></div>`;
  }).join("");
}

function renderPath() {
  $("attackPath").classList.remove("observed-connections");
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
  resetReplay();
  clearInterval(timer);
  stopLiveReplay();
  selectView("analysis");
  showScriptedMode();
  if (step >= session.stages.length - 1) {
    step = 0;
    renderState();
  }
  renderState();
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
  clearTrafficEvidence();
  analysisReport = null;
  lastNetwork = null;
  $("hostFilter").value = "";
  $("exportReport").disabled = true;
  $("exportStatus").textContent = "";
  $("compatibilityNotice").hidden = true;
  clearInterval(timer);
  stopLiveReplay();
  step = 0;
  resetSignalGraph();
  for (const id of ["riskValue", "nextStage", "targetHost", "confidence"]) $(id).textContent = "—";
  for (const id of ["forecastChart", "timeline", "features", "attackPath"]) $(id).replaceChildren();
  $("riskRing").parentElement.style.background = "var(--line)";
  $("riskTrend").textContent = "NO DATA";
  $("riskText").textContent = "Awaiting model inference";
  $("eta").textContent = "Requires 60 seconds of traffic";
  $("targetLabel").textContent = "OBSERVED DESTINATION";
  $("pathTitle").textContent = "Observed host connections";
  $("pathBadge").textContent = "PACKET EVIDENCE";
  $("pathLegend").textContent = "Observed connections appear as the capture is processed.";
  $("connectionGraph").hidden = false;
  drawConnectionGraph({connections: []});
  $("source").textContent = "No capture selected";
  $("modelStatus").textContent = "AWAITING CAPTURE";
  $("streamStatus").textContent = "NO CAPTURE";
  $("forecastLegend").textContent = "+5s / +10s / +15s · Forecasts appear after warm-up";
  $("forecastChart").textContent = "No model output yet";
  $("explanation").textContent = "Upload a capture to inspect feature contributions.";
  $("explainMethod").textContent = "Integrated gradients · available after model warm-up";
  $("labReplayStats").textContent = "No capture loaded";
  $("labReplayDetail").textContent = "PCAP / PCAPNG · At least 60 seconds of usable traffic";
  $("pcapFile").value = "";
  setSituationBrief("NO DATA", "Ready to analyse a capture.", "Packet activity and connections will come from your uploaded file.", "Model scores remain exploratory until validated for this network.", "Upload a capture to begin.", "unknown");
}

async function uploadPcap(file) {
  clearTrafficEvidence();
  $("uploadPcap").disabled = true;
  $("reset").disabled = true;
  analysisReport = null;
  lastNetwork = null;
  $("hostFilter").value = "";
  $("exportReport").disabled = true;
  $("compatibilityNotice").hidden = true;
  $("exportStatus").textContent = "";
  replayPaused = false;
  replayComplete = false;
  $("pauseReplay").textContent = "Pause replay";
  resetSignalGraph();
  $("connectionGraph").hidden = false;
  drawConnectionGraph({connections:[]});
  $("labReplayStats").textContent = "Loading capture";
  clearInterval(timer);
  stopLiveReplay();
  $("nextStage").textContent = "WAITING";
  $("eta").textContent = "Collecting capture history";
  $("targetHost").textContent = "Not inferred from this model";
  $("confidence").textContent = "—";
  $("forecastChart").replaceChildren();
  $("forecastLegend").textContent = "Trained forecast horizons: +5s / +10s / +15s · shadow mode";
  $("timeline").replaceChildren();
  $("pathTitle").textContent = "Observed host connections";
  $("pathBadge").textContent = "PACKET EVIDENCE";
  $("targetLabel").textContent = "OBSERVED DESTINATION";
  $("pathLegend").textContent = "Connections seen so far · not a predicted attack path";
  $("attackPath").textContent = "Reading connections from the capture…";
  $("features").replaceChildren();
  $("explanation").textContent = "Waiting for model evidence from this capture.";
  $("explainMethod").textContent = "No explanation available until the model is ready.";
  $("streamStatus").textContent = "WARMING UP";
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
  currentReplayId = replay.replay_id;
  analysisReport = {schema_version: 1, capture: replay, recorded_at: new Date().toISOString(), scope: "Observed packet replay and exploratory forecasts; not validated attack detection", status: "running", complete: false, updates: [], omitted_older_updates: 0};
  $("exportReport").disabled = false;
  connectReplay(replay.replay_id);
}

function connectReplay(replayId) {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${location.host}/ws/replays/${replayId}`);
  liveSocket = socket;
  socket.addEventListener("open", () => {
    if (liveSocket !== socket) return;
    liveSocket.send(JSON.stringify({type: "auth", token: accessToken}));
  });
  socket.addEventListener("message", (event) => {
    if (liveSocket !== socket) return;
    const update = JSON.parse(event.data);
    if (update.type === "pong") return;
    replayPending = false;
    if (update.type === "connected") {
      $("modelStatus").textContent = "MODEL WARMING UP 0 / 12";
      $("modelStatus").classList.add("live-model");
      $("pauseReplay").disabled = false;
      clearInterval(replayHeartbeat);
      replayHeartbeat = setInterval(() => {
        if (liveSocket === socket && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({type: "ping"}));
      }, 20000);
      scheduleReplay();
      return;
    }
    if (update.type === "error") { markReplayInterrupted(update.detail || "Replay failed"); return; }
    if (update.type !== "replay_update") return;
    const inference = update.inference;
    if (analysisReport) {
      analysisReport.updates.push(update);
      if (analysisReport.updates.length > 720) { analysisReport.updates.shift(); analysisReport.omitted_older_updates++; }
      analysisReport.complete = update.complete;
      analysisReport.status = update.complete ? "complete" : replayPaused ? "paused" : "running";
    }
    replayComplete = update.complete;
    $("pauseReplay").disabled = update.complete;
    if (inference.feature_compatibility) {
      $("compatibilityNotice").hidden = inference.feature_compatibility.compatible;
      $("compatibilityNotice").textContent = inference.feature_compatibility.detail;
    }
    updateSignalGraph(update.states);
    $("labReplayStats").textContent = `${update.processed_packets.toLocaleString()} packets · ${Math.round(update.elapsed_seconds)}s processed`;
    $("labReplayDetail").textContent = `${update.observed_network?.host_count ?? 0} hosts in recent packet scope · ${update.complete ? "Replay complete" : "Replay active"}`;

    $("streamStatus").textContent = update.complete ? "COMPLETE" : replayPaused ? "PAUSED" : "PCAP REPLAY";
    $("timeline").textContent = `Capture progress: ${Math.round(update.elapsed_seconds || 0)} seconds · ${inference.warmup_states ?? inference.sequence_states ?? 12} history windows`;
    if (!inference.model_ready) {
      $("modelStatus").textContent = `MODEL WARMING UP ${inference.warmup_states} / ${inference.required_states}`;
      $("riskValue").textContent = "--";
      $("riskText").textContent = `Collected ${inference.warmup_states} of ${inference.required_states} five-second windows`;
      setSituationBrief("LEARNING", "The model needs more traffic history.", `It has collected ${inference.warmup_states} of ${inference.required_states} required windows.`, "The temporal model compares a full minute of behaviour, not one isolated packet.", "Keep the replay running until the model becomes ready.", "unknown");
    } else {
      $("modelStatus").textContent = "TRAINED LSTM · LIVE INFERENCE";
      applyLiveForecast(inference.forecast, inference.feature_contributions, inference.explanation_method, inference.uncertainty, inference.temporal_contributions);
    }
    renderObservedNetwork(update.observed_network, inference.uncertainty);
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
  socket.addEventListener("error", () => {
    if (liveSocket !== socket) return;
    clearInterval(replayHeartbeat);
    clearInterval(liveTimer);
    $("pauseReplay").disabled = true;
    markReplayInterrupted("LIVE CONNECTION ERROR");
    $("modelStatus").classList.remove("live-model");
    setSituationBrief("CONNECTION ERROR", "The live replay connection stopped.", "The dashboard cannot currently receive new PCAP windows from the server.", "Any risk value still visible may be out of date.", "Check the server connection, then upload the capture again.", "danger");
  });
  socket.addEventListener("close", (event) => {
    if (liveSocket !== socket) return;
    clearInterval(replayHeartbeat);
    clearInterval(liveTimer);
    $("pauseReplay").disabled = true;
    if (!replayComplete) markReplayInterrupted("REPLAY STOPPED · check connection or permissions");
    if (event.code === 4401) {
      sessionStorage.removeItem("shadownetToken");
      accessToken = "";
      $("modelStatus").textContent = "LOGIN EXPIRED · UPLOAD THE PCAP AGAIN";
      setSituationBrief("LOGIN REQUIRED", "The secure replay session expired.", "The one-hour login token is no longer valid.", "The server rejected the live stream to prevent unauthenticated access.", "Upload the PCAP again and sign in when prompted.", "watch");
    }
  });
}

function renderObservedNetwork(network, uncertainty) {
  if (!network) return;
  lastNetwork = network;
  renderTrafficEvidence(network);
  const filter = $("hostFilter").value.trim().toLowerCase();
  const connections = network.connections.filter(c => !filter || c.src.toLowerCase().includes(filter) || c.dst.toLowerCase().includes(filter));
  drawConnectionGraph({...network, connections});
  const panel = $("attackPath");
  panel.replaceChildren();
  panel.classList.add("observed-connections");
  for (const connection of connections) {
    const row = document.createElement("div");
    row.className = "observed-connection";
    const route = document.createElement("strong");
    route.textContent = `${connection.src} → ${connection.dst}`;
    const detail = document.createElement("span");
    const protocol = ({1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"})[connection.protocol] || `IP ${connection.protocol}`;
    const port = [6,17].includes(connection.protocol) ? ` · destination port ${connection.destination_port}` : "";
    detail.textContent = `${protocol}${port} · ${connection.packets} packets`;
    row.append(route, detail);
    panel.append(row);
  }
  if (!connections.length) panel.textContent = filter ? "No matching connections in the displayed top six." : "No IP connections processed yet.";
  $("targetHost").textContent = network.connections[0]?.dst || "Waiting for packets";
  $("pathLegend").textContent = `${network.host_count} hosts · ${network.destination_port_count} destination ports · latest ${network.packets_in_scope} processed packets. Observed connections, not an inferred attack path.`;
  if (uncertainty && uncertainty.status !== "in_distribution") {
    const pattern = network.destination_port_count >= 10
      ? `Connections span ${network.destination_port_count} destination ports; review for approved service discovery or scanning.`
      : `${network.syn_requests} TCP connection-start packets were observed; this alone does not establish an attack.`;
    setSituationBrief("ANALYSED · MODEL CAUTION", "Capture analysed. Review the observed network activity.",
      `${network.packets_in_scope} recent packets connect ${network.host_count} hosts across ${network.destination_port_count} destination ports. ${pattern}`,
      "Packet evidence is available, but this traffic differs from the model's training distribution. Forecast scores are exploratory and alerts are suppressed.",
      "Inspect the connections and source activity in this workspace. Use independent labelled local captures to validate forecasts before operational use.", "watch");
  }
}

function applyLiveForecast(forecast, contributions = [], method = "integrated_gradients", uncertainty = null, temporal = []) {
  if (!forecast.length) return;
  const current = forecast[0];
  $("riskTrend").textContent = "● SHADOW FORECAST";
  $("riskValue").textContent = String(Math.round(current.risk)).padStart(2, "0");
  $("riskRing").parentElement.style.background = `conic-gradient(var(--lime) ${current.risk}%, #21312c 0)`;
  $("riskText").textContent = `Live +${current.offset_seconds}s model forecast`;
  $("nextStage").textContent = current.stage.toUpperCase();
  $("targetHost").textContent = "Not inferred from this model";
  $("confidence").textContent = `${Math.round(current.confidence)}%`;
  $("eta").textContent = `Proxy stage estimate at +${current.offset_seconds}s`;
  if (uncertainty && uncertainty.status !== "in_distribution") {
    $("modelStatus").textContent = "CAPTURE ANALYSED · MODEL CAUTION";
    $("modelStatus").classList.remove("live-model");
    $("riskText").textContent = "Experimental score · outside model training distribution";
    $("eta").textContent = "Analyst review required · no automated alert";
    setSituationBrief("UNKNOWN TRAFFIC", "This traffic does not resemble the model's validated training data.", "The statistical pattern falls outside the network behaviour the model knows.", "The displayed probability may not be trustworthy on this network.", "Review the capture manually and calibrate the model on representative local traffic before using alerts.", "unknown");
  } else if (uncertainty) {
    $("modelStatus").textContent = "SHADOW MODE · OPERATIONAL ALERTS DISABLED";
    const roundedRisk = Math.round(current.risk);
    setSituationBrief("SHADOW FORECAST", `Experimental model score: ${roundedRisk}% at +${current.offset_seconds}s.`, `The strongest forecast points toward the ${current.stage} stage.`, current.shadow_alert ? "The score crossed the experimental threshold; no operational alert was issued." : "The score remains below the experimental threshold.", "Compare predictions against labelled outcomes. Model validation is incomplete.", "unknown");
  }
  $("forecastChart").innerHTML = forecast.map((point) => {
    const uncertainty = 0; // Heuristic risk margins are not validated confidence intervals.
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
  button.disabled = true;
  try {
  const response = await authenticatedFetch("/api/simulate", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({action: selectedAction})});
  if (!response.ok) throw new Error((await response.json()).detail || "Simulation failed");
  const outcome = await response.json();
  $("beforeRisk").textContent = `${outcome.before}%`;
  $("afterRisk").textContent = `${outcome.after}%`;
  $("delta").textContent = `−${outcome.reduction} pts projected risk`;
  $("simExplanation").textContent = `${outcome.explanation} ${outcome.disclaimer} Method: ${outcome.method.replaceAll("_", " ")}.`;
  } finally {
    button.textContent = "Run simulation";
    button.disabled = false;
  }
}

$("play").addEventListener("click", startReplay);
$("reset").addEventListener("click", resetReplay);
$("simulate").addEventListener("click", () => simulate().catch((error) => { $("simExplanation").textContent = error.message; }));
$("uploadPcap").addEventListener("click", () => $("pcapFile").click());
$("pcapFile").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) uploadPcap(file).catch((error) => {
    $("modelStatus").textContent = error.message.toUpperCase();
    setSituationBrief("UPLOAD FAILED", "The capture could not be analysed.", error.message, "No new model result was produced.", "Correct the reported problem and upload the PCAP again.", "danger");
  }).finally(() => { $("uploadPcap").disabled = false; $("reset").disabled = false; });
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

function selectView(name) {
  document.querySelectorAll(".workspace-view").forEach(view => { view.hidden = view.id !== `view-${name}`; });
  document.querySelectorAll(".workspace-nav button").forEach(button => {
    if (button.dataset.view === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
}
document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => selectView(button.dataset.view)));

$("pauseReplay").addEventListener("click", () => {
  replayPaused = !replayPaused;
  if (analysisReport) analysisReport.status = replayPaused ? "paused" : "running";
  $("pauseReplay").textContent = replayPaused ? "Resume replay" : "Pause replay";
  $("streamStatus").textContent = replayPaused ? "PAUSED" : "PCAP REPLAY";
  scheduleReplay();
});
$("replaySpeed").addEventListener("change", scheduleReplay);
$("exportReport").addEventListener("click", exportAnalysis);
$("hostFilter").addEventListener("input", () => { if (lastNetwork) renderObservedNetwork(lastNetwork); });

$("closeAnalysis").addEventListener("click", () => $("analysisDialog").close());

let captureEvaluation = null;
async function readEvaluationJSON(file) {
  if (file.size > 5 * 1024 * 1024) throw new Error("Evaluation JSON files must be at most 5 MB each.");
  return JSON.parse(await file.text());
}
async function evaluateCurrentCapture() {
  const button = $("evaluateCapture"); button.disabled = true;
  captureEvaluation = null;
  $("exportEvaluation").disabled = true;
  $("evaluationResults").replaceChildren();
  try {
    const labelsFile = $("evaluationLabels").files[0];
    if (!labelsFile) throw new Error("Select a labelled timeline or capture manifest JSON first.");
    const reportFile = $("evaluationReport").files[0];
    const report = reportFile ? await readEvaluationJSON(reportFile) : analysisReport;
    if (!report || !report.updates.length) throw new Error("Replay a capture first or select an analysis export.");
    const labels = await readEvaluationJSON(labelsFile);
    // Snapshot the current replay before login or network waits can advance it.
    const body = JSON.stringify({report, labels});
    $("evaluationStatus").textContent = "Comparing retained forecasts against labelled future windows…";
    const response = await authenticatedFetch("/api/evaluate-capture", {method: "POST", headers: {"Content-Type": "application/json"}, body});
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Invalid evaluation input");
    captureEvaluation = result;
    $("exportEvaluation").disabled = false;
    $("evaluationStatus").textContent = `Capture ${result.capture_sha256.slice(0,12)}… · evaluated through ${result.observed_until_seconds}s of ${result.capture_duration_seconds}s · ${result.omitted_older_updates} older updates omitted. Labels: ${result.label_provenance}.`;
    const percent = value => value == null ? "N/A" : `${(value*100).toFixed(1)}%`;
    for (const horizon of result.horizons) {
      const card = document.createElement("article"); card.className = "evaluation-card";
      const heading = document.createElement("h3"); heading.textContent = `+${horizon.offset_seconds}s forecast`;
      const raw = horizon.raw_classifier;
      const summary = document.createElement("p"); summary.textContent = `${raw.support} labelled predictions · raw F1 ${percent(raw.f1)} · recall ${percent(raw.recall)} · false-positive rate ${percent(raw.false_positive_rate)}`;
      const counts = document.createElement("p"); counts.textContent = `Raw counts: ${raw.tp} true positives / ${raw.fp} false positives / ${raw.fn} misses / ${raw.tn} true negatives.`;
      const coverage = document.createElement("p"); coverage.textContent = `${percent(horizon.rejection_rate)} rejected · ${horizon.accepted_only.support} accepted · ${horizon.rejected_attack} attack windows rejected. Rejection is not correct detection.`;
      const excluded = document.createElement("p"); excluded.textContent = `Excluded: ${horizon.outside_observed_capture} beyond processed history; ${horizon.ambiguous_label_windows} mixed-label windows.`;
      card.append(heading, summary, counts, coverage, excluded); $("evaluationResults").append(card);
    }
    const note = document.createElement("p"); note.className = "evaluation-note"; note.textContent = "N/A means the denominator is absent, not zero errors. These are supplied-artifact measurements, not independently verified deployment claims. Thresholds are unchanged; rejected windows are excluded from accepted-only metrics."; $("evaluationResults").append(note);
  } catch (error) { $("evaluationStatus").textContent = error.message; }
  finally { button.disabled = false; }
}
$("evaluateCapture").addEventListener("click", evaluateCurrentCapture);
$("exportEvaluation").addEventListener("click", () => { if (captureEvaluation) showJsonReport(captureEvaluation, "shadownet-evaluation.json"); });
