let session;
let step = 0;
let timer;
let selectedAction = "close_port";
let liveSocket;
let liveTimer;
let accessToken = sessionStorage.getItem("shadownetToken") || "";

const $ = (id) => document.getElementById(id);

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
  [session] = await Promise.all([
    fetch("/api/session").then((response) => response.json()),
    loadEvidence(),
  ]);
  $("source").textContent = session.source;
  renderForecast();
  renderPath();
  renderTimeline();
  renderState();
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
  const body = new FormData();
  body.append("file", file);
  const response = await authenticatedFetch("/api/replays?window_seconds=5", {method: "POST", body});
  if (!response.ok) throw new Error((await response.json()).detail || "Upload failed");
  const replay = await response.json();
  $("source").textContent = `${replay.filename} · ${(replay.size_bytes / 1024).toFixed(1)} KB`;
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
      } else {
        $("modelStatus").textContent += " · REPLAY COMPLETE";
      }
    }
  });
  liveSocket.addEventListener("error", () => {
    $("modelStatus").textContent = "LIVE CONNECTION ERROR";
    $("modelStatus").classList.remove("live-model");
  });
  liveSocket.addEventListener("close", (event) => {
    if (event.code === 4401) {
      sessionStorage.removeItem("shadownetToken");
      accessToken = "";
      $("modelStatus").textContent = "LOGIN EXPIRED · UPLOAD THE PCAP AGAIN";
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
  } else if (uncertainty) {
    $("modelStatus").textContent = "CALIBRATED LSTM · IN-DISTRIBUTION";
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
  if (file) uploadPcap(file).catch((error) => { $("modelStatus").textContent = error.message.toUpperCase(); });
  event.target.value = "";
});
$("actions").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  selectedAction = button.dataset.action;
  document.querySelectorAll("#actions button").forEach((item) => item.classList.toggle("selected", item === button));
});

boot().catch((error) => {
  $("source").textContent = `API unavailable: ${error.message}`;
});
