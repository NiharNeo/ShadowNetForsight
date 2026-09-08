from __future__ import annotations

from pathlib import Path
import json
import re
import tempfile
from typing import Any, Literal, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.replay_service import ReplayRegistry
from backend.inference_service import LSTMInferenceService
from backend.telemetry_service import TelemetryRegistry
from backend.security import ROLE_LEVEL, Principal, SecurityManager
from pipeline.mitigation_simulator import simulate_mitigation
from pipeline.pcap_calibration import fit_pcap_domain_calibration


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"

app = FastAPI(title="ShadowNet ForeSight", version="0.1.0")
app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")
inference_service = LSTMInferenceService(ROOT / "models" / "cic2018-phase1-lstm" / "lstm.pt")
replays = ReplayRegistry(ROOT / "data" / "uploads", inference_service)
telemetry = TelemetryRegistry(inference_service)
security = SecurityManager(ROOT / "data" / "shadownet.db")
MAX_PCAP_BYTES = 250 * 1024 * 1024


STAGES = [
    {
        "name": "Normal",
        "risk": 8,
        "confidence": 96,
        "host": "Edge gateway",
        "eta": "No progression",
        "event": "Baseline traffic established",
        "detail": "Connection volume and protocol mix are within the learned baseline.",
        "features": [("Flow volume", 12), ("SYN / ACK ratio", 8), ("Failed logins", 3)],
    },
    {
        "name": "Reconnaissance",
        "risk": 31,
        "confidence": 89,
        "host": "10.0.0.5",
        "eta": "Initial access in ~90 sec",
        "event": "Port sweep emerging",
        "detail": "One external source has touched 18 previously unseen services.",
        "features": [("Unique ports", 68), ("SYN / ACK ratio", 54), ("New source", 41)],
    },
    {
        "name": "Reconnaissance",
        "risk": 52,
        "confidence": 86,
        "host": "10.0.0.5",
        "eta": "Initial access in ~60 sec",
        "event": "SSH enumeration detected",
        "detail": "Sequential usernames and failed handshakes now form a temporal pattern.",
        "features": [("Unique ports", 83), ("Failed SSH logins", 71), ("Burst IAT", 49)],
    },
    {
        "name": "Initial Access",
        "risk": 71,
        "confidence": 82,
        "host": "10.0.0.5",
        "eta": "Lateral movement in ~60 sec",
        "event": "Access attempt forecast",
        "detail": "The rollout predicts successful SSH access before the labelled event occurs.",
        "features": [("Failed SSH logins", 91), ("Username sequence", 76), ("Sensitive target", 63)],
    },
    {
        "name": "Lateral Movement",
        "risk": 82,
        "confidence": 78,
        "host": "10.0.0.12",
        "eta": "Exfiltration in ~2 min",
        "event": "Internal pivot forecast",
        "detail": "Credential reuse and east-west connections point toward the database tier.",
        "features": [("Credential reuse", 94), ("East-west flows", 84), ("SMB activity", 69)],
    },
]


class SimulationRequest(BaseModel):
    action: Literal["block_ip", "close_port", "isolate_host", "rate_limit"]


class AdvanceRequest(BaseModel):
    seconds: float = 5.0


class TelemetryCreateRequest(BaseModel):
    source: Literal["auto", "cowrie", "netflow", "ipfix", "kafka"] = "auto"
    window_seconds: int = 5
    allowed_lateness: float = 2.0
    calibration_domain: Optional[str] = None


class TelemetryBatchRequest(BaseModel):
    records: list[dict[str, Any]]
    flush: bool = False


class KafkaConnectRequest(BaseModel):
    bootstrap_servers: str
    topic: str
    group_id: str = "shadownet-foresight"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: Literal["viewer", "operator", "admin"]


def _principal(request: Request, minimum_role: str) -> Principal:
    authorization = request.headers.get("authorization", "")
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    principal = security.verify_token(token)
    if principal is None:
        raise HTTPException(status_code=401, detail="Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})
    if ROLE_LEVEL[principal.role] < ROLE_LEVEL[minimum_role]:
        raise HTTPException(status_code=403, detail=f"{minimum_role} role required")
    return principal


@app.middleware("http")
async def audit_mutations(request: Request, call_next):
    response = await call_next(request)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path != "/api/auth/login":
        authorization = request.headers.get("authorization", "")
        principal = security.verify_token(authorization[7:]) if authorization.lower().startswith("bearer ") else None
        security.audit(principal.username if principal else "anonymous", request.method, request.url.path, response.status_code,
                       {"client": request.client.host if request.client else "unknown"})
    return response


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/session")
def session() -> dict:
    return {
        "session_id": "SNF-DEMO-042",
        "source": "CIC-IDS2018 replay / SSH brute-force scenario",
        "window_seconds": 5,
        "lead_time_seconds": 65,
        "stages": STAGES,
        "forecast": [
            {"offset": "Now", "risk": 52, "low": 44, "high": 60, "stage": "Recon"},
            {"offset": "+30s", "risk": 63, "low": 52, "high": 72, "stage": "Recon"},
            {"offset": "+60s", "risk": 71, "low": 59, "high": 81, "stage": "Initial Access"},
            {"offset": "+90s", "risk": 82, "low": 66, "high": 91, "stage": "Lateral Move"},
        ],
        "path": [
            {"id": "attacker", "label": "185.220.101.4", "kind": "external"},
            {"id": "edge", "label": "Edge gateway", "kind": "observed"},
            {"id": "web", "label": "10.0.0.5 : 22", "kind": "targeted"},
            {"id": "db", "label": "10.0.0.12 : 445", "kind": "predicted"},
        ],
    }


@app.post("/api/simulate")
def simulate(request: SimulationRequest, http_request: Request) -> dict:
    _principal(http_request, "operator")
    result = simulate_mitigation(request.action)
    result["explanation"] = f"Intervention changed {len(result['changed_edges'])} attack-path edge(s); risk is estimated by repeated path propagation."
    return result


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "model": "ready" if inference_service.available else "unavailable",
        "model_source": "CSE-CIC-IDS2018 five-day, multi-family whole-day training partition",
        "decision_thresholds": inference_service.thresholds,
        "calibration": "per_horizon_temperature_scaling",
        "ood_rejection": "ready" if inference_service.ood_threshold is not None else "unavailable",
    }


@app.get("/api/evidence")
def evidence() -> dict:
    summary_path = ROOT / "models" / "cic2018-multiday-lstm" / "evaluation-summary.json"
    return json.loads(summary_path.read_text(encoding="utf-8"))


@app.get("/api/calibration/profiles")
def calibration_profiles() -> list[dict]:
    return [{
        "domain": domain,
        "sample_count": profile.get("sample_count", 0),
        "validation_macro_f1": profile.get("validation_macro_f1"),
        "source_type": profile.get("source_type", "processed_validation_partition"),
        "warning": profile.get("warning"),
    } for domain, profile in sorted(inference_service.domain_calibrations.items())]


@app.post("/api/calibration/profiles")
async def create_calibration_profile(
    request: Request,
    domain: str = Form(...),
    benign_files: list[UploadFile] = File(...),
    attack_files: list[UploadFile] = File(...),
) -> dict:
    _principal(request, "operator")
    domain = domain.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", domain):
        raise HTTPException(status_code=422, detail="Profile name must be 2-40 lowercase letters, numbers or hyphens")
    if domain in inference_service.domain_calibrations:
        raise HTTPException(status_code=409, detail="A calibration profile with this name already exists")
    if not benign_files or not attack_files:
        raise HTTPException(status_code=422, detail="Provide at least one benign and one attack PCAP")
    with tempfile.TemporaryDirectory(prefix="calibration-", dir=ROOT / "data") as directory:
        temp_root = Path(directory)
        saved: dict[str, list[Path]] = {"benign": [], "attack": []}
        total_size = 0
        for label, uploads in (("benign", benign_files), ("attack", attack_files)):
            for index, upload in enumerate(uploads):
                suffix = Path(upload.filename or "capture.pcap").suffix.lower()
                if suffix not in {".pcap", ".pcapng"}:
                    raise HTTPException(status_code=415, detail="Calibration accepts only .pcap and .pcapng files")
                path = temp_root / f"{label}-{index}{suffix}"
                with path.open("wb") as stream:
                    while chunk := await upload.read(1024 * 1024):
                        total_size += len(chunk)
                        if total_size > MAX_PCAP_BYTES:
                            raise HTTPException(status_code=413, detail="Calibration uploads exceed the 250 MB prototype limit")
                        stream.write(chunk)
                saved[label].append(path)
        try:
            output = inference_service.checkpoint_path.parent / "domain_calibrations" / f"{domain}.json"
            profile = fit_pcap_domain_calibration(inference_service.checkpoint_path, saved["benign"], saved["attack"], domain, output)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    inference_service.domain_calibrations[domain] = profile
    return profile


@app.post("/api/auth/login")
def login(request: LoginRequest) -> dict:
    token = security.authenticate(request.username, request.password)
    if token is None:
        security.audit(request.username, "LOGIN", "/api/auth/login", 401)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    principal = security.verify_token(token)
    security.audit(request.username, "LOGIN", "/api/auth/login", 200)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600, "role": principal.role}


@app.get("/api/auth/me")
def current_user(request: Request) -> dict:
    principal = _principal(request, "viewer")
    return {"username": principal.username, "role": principal.role}


@app.post("/api/admin/users")
def create_user(request: Request, body: UserCreateRequest) -> dict:
    _principal(request, "admin")
    try:
        security.create_user(body.username, body.password, body.role)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=409, detail="Username already exists") from error
    return {"username": body.username, "role": body.role}


@app.get("/api/admin/users")
def list_users(request: Request) -> list[dict]:
    _principal(request, "admin")
    return security.list_users()


@app.get("/api/admin/audit")
def audit_log(request: Request, limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    _principal(request, "admin")
    return security.audit_entries(limit)


@app.get("/api/admin/audit/verify")
def verify_audit_log(request: Request) -> dict:
    _principal(request, "admin")
    return security.verify_audit_chain()


@app.post("/api/telemetry/streams")
def create_telemetry_stream(request: TelemetryCreateRequest, http_request: Request) -> dict:
    _principal(http_request, "operator")
    if not 1 <= request.window_seconds <= 60 or not 0 <= request.allowed_lateness <= 60:
        raise HTTPException(status_code=422, detail="window_seconds must be 1-60 and allowed_lateness 0-60")
    if request.calibration_domain and request.calibration_domain not in inference_service.domain_calibrations:
        raise HTTPException(status_code=422, detail=f"Unknown calibration domain: {request.calibration_domain}")
    stream_id, handle = telemetry.create(request.source, request.window_seconds, request.allowed_lateness, request.calibration_domain)
    return {"stream_id": stream_id, "source": request.source, "calibration_domain": request.calibration_domain or "global", **handle.stream.status()}


@app.post("/api/telemetry/streams/{stream_id}/events")
def ingest_telemetry(stream_id: str, request: TelemetryBatchRequest, http_request: Request) -> dict:
    _principal(http_request, "operator")
    if len(request.records) > 10_000:
        raise HTTPException(status_code=413, detail="A batch may contain at most 10,000 records")
    try:
        return telemetry.get(stream_id).ingest(request.records, request.flush)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/api/telemetry/streams/{stream_id}")
def telemetry_status(stream_id: str, request: Request) -> dict:
    _principal(request, "viewer")
    try:
        handle = telemetry.get(stream_id)
        return {"source": handle.source, **handle.stream.status(),
                "calibration_domain": handle.inference.domain or "global",
                "warmup_states": len(handle.inference.states), "required_states": inference_service.sequence_length,
                "host_graph": handle.graph.features()}
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.delete("/api/telemetry/streams/{stream_id}")
def delete_telemetry_stream(stream_id: str, request: Request) -> dict[str, str]:
    _principal(request, "operator")
    try:
        telemetry.remove(stream_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return {"deleted": stream_id}


@app.post("/api/telemetry/streams/{stream_id}/kafka")
def connect_kafka(stream_id: str, body: KafkaConnectRequest, request: Request) -> dict:
    _principal(request, "operator")
    if not body.bootstrap_servers.strip() or not body.topic.strip():
        raise HTTPException(status_code=422, detail="bootstrap_servers and topic are required")
    try:
        telemetry.connect_kafka(stream_id, body.bootstrap_servers, body.topic, body.group_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"stream_id": stream_id, "kafka_connected": True, "topic": body.topic, "group_id": body.group_id}


@app.post("/api/replays")
async def create_replay(
    request: Request,
    file: UploadFile = File(...),
    window_seconds: int = Query(5, ge=1, le=60),
    calibration_domain: Optional[str] = Query(None),
) -> dict:
    _principal(request, "operator")
    if calibration_domain and calibration_domain not in inference_service.domain_calibrations:
        raise HTTPException(status_code=422, detail=f"Unknown calibration domain: {calibration_domain}")
    suffix = Path(file.filename or "capture.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=415, detail="Only .pcap and .pcapng files are accepted.")
    destination = replays.allocate_path(suffix)
    size = 0
    try:
        with destination.open("wb") as stream:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_PCAP_BYTES:
                    raise HTTPException(status_code=413, detail="PCAP exceeds the 250 MB prototype limit.")
                stream.write(chunk)
        replay_id, handle = replays.create(destination, file.filename or destination.name, window_seconds, calibration_domain)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {"replay_id": replay_id, "filename": handle.original_name, "size_bytes": size,
            "calibration_domain": calibration_domain or "global", **handle.replay.status()}


@app.post("/api/replays/{replay_id}/advance")
def advance_replay(replay_id: str, request: AdvanceRequest, http_request: Request) -> dict:
    _principal(http_request, "operator")
    try:
        return replays.get(replay_id).advance(request.seconds)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/api/replays/{replay_id}")
def replay_status(replay_id: str, request: Request) -> dict:
    _principal(request, "viewer")
    try:
        return replays.get(replay_id).replay.status()
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.delete("/api/replays/{replay_id}")
def delete_replay(replay_id: str, request: Request) -> dict[str, str]:
    _principal(request, "operator")
    try:
        replays.remove(replay_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return {"deleted": replay_id}


@app.websocket("/ws/replays/{replay_id}")
async def replay_socket(websocket: WebSocket, replay_id: str) -> None:
    try:
        handle = replays.get(replay_id)
    except KeyError:
        await websocket.close(code=4404, reason="Replay session not found")
        return
    await websocket.accept()
    try:
        authentication = await websocket.receive_json()
    except (WebSocketDisconnect, ValueError):
        return
    principal = security.verify_token(str(authentication.get("token", "")))
    if authentication.get("type") != "auth" or principal is None or ROLE_LEVEL[principal.role] < ROLE_LEVEL["viewer"]:
        await websocket.close(code=4401, reason="Valid viewer token required")
        return
    await websocket.send_json({"type": "connected", "replay_id": replay_id, **handle.replay.status()})
    try:
        while True:
            message = await websocket.receive_json()
            seconds = float(message.get("seconds", 5))
            if seconds <= 0 or seconds > 60:
                await websocket.send_json({"type": "error", "detail": "seconds must be between 0 and 60"})
                continue
            await websocket.send_json({"type": "replay_update", **handle.advance(seconds)})
    except WebSocketDisconnect:
        return
