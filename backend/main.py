from __future__ import annotations

from pathlib import Path
import asyncio
from contextlib import asynccontextmanager, suppress
import logging
import os
import sqlite3
import time
from uuid import uuid4
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware
from scapy.error import Scapy_Exception
import json
import re
import tempfile
from typing import Any, Literal, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from backend.config import Settings
from backend.http_limits import BodyLimitMiddleware

from backend.replay_service import ReplayRegistry, CapacityError
from backend.inference_service import LSTMInferenceService
from backend.telemetry_service import TelemetryRegistry
from backend.security import ROLE_LEVEL, Principal, SecurityManager
from pipeline.evaluate_capture import evaluate as evaluate_capture
from pipeline.mitigation_simulator import simulate_mitigation
from pipeline.pcap_calibration import fit_pcap_domain_calibration


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"

settings = Settings.from_env()
settings.data_dir.mkdir(parents=True, exist_ok=True)
inference_service = LSTMInferenceService(settings.checkpoint, calibration_dir=settings.data_dir / "calibrations")
replays = ReplayRegistry(settings.data_dir / "uploads", inference_service, settings.max_sessions, settings.session_ttl_seconds)
telemetry = TelemetryRegistry(inference_service, settings.max_sessions, settings.session_ttl_seconds)
security = SecurityManager(settings.data_dir / "shadownet.db")
MAX_PCAP_BYTES = settings.max_pcap_bytes
logger = logging.getLogger("shadownet.api")
calibration_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app):
    if settings.production and not inference_service.available:
        raise RuntimeError("Production requires a loadable model checkpoint")
    async def expire_sessions():
        while True:
            await asyncio.sleep(60)
            await run_in_threadpool(replays.cleanup)
            await run_in_threadpool(telemetry.cleanup)
    task = asyncio.create_task(expire_sessions())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await run_in_threadpool(replays.close)
        await run_in_threadpool(telemetry.close)


app = FastAPI(title="ShadowNet ForeSight", version="0.2.0", lifespan=lifespan,
              docs_url=None if settings.production else "/docs",
              redoc_url=None if settings.production else "/redoc",
              openapi_url=None if settings.production else "/openapi.json")
app.add_middleware(BodyLimitMiddleware, upload_limit=MAX_PCAP_BYTES)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))
app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    # Do not echo passwords, uploaded bytes or NaN/Infinity in validation errors.
    return JSONResponse({"detail": [{"loc": item["loc"], "msg": item["msg"], "type": item["type"]} for item in error.errors()]}, status_code=422)


@app.exception_handler(CapacityError)
async def capacity_error(request, error):
    return JSONResponse({"detail": str(error)}, status_code=429, headers={"Retry-After": "60"})



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
    model_config = ConfigDict(allow_inf_nan=False)
    seconds: float = Field(5.0, gt=0, le=60)


class TelemetryCreateRequest(BaseModel):
    source: Literal["auto", "cowrie", "netflow", "ipfix", "kafka"] = "auto"
    model_config = ConfigDict(allow_inf_nan=False)
    window_seconds: Literal[5] = 5
    allowed_lateness: float = Field(2.0, ge=0, le=60)
    calibration_domain: Optional[str] = None


class TelemetryBatchRequest(BaseModel):
    records: list[dict[str, Any]]
    flush: bool = False


class KafkaConnectRequest(BaseModel):
    bootstrap_servers: str
    topic: str
    group_id: str = "shadownet-foresight"


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
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
    request_id = uuid4().hex
    started = time.monotonic()
    mutation = request.method in {"POST", "PUT", "PATCH", "DELETE"}
    principal = None
    try:
        # Authorize uploads before FastAPI consumes multipart bodies.
        if mutation and request.url.path != "/api/auth/login":
            minimum_role = "operator"
            if request.url.path == "/api/auth/logout":
                minimum_role = "viewer"
            elif request.url.path == "/api/calibration/profiles" or request.url.path.startswith("/api/admin/") or request.url.path.endswith("/kafka"):
                minimum_role = "admin"
            principal = await run_in_threadpool(_principal, request, minimum_role)
        response = await call_next(request)
    except HTTPException as error:
        response = JSONResponse({"detail": error.detail}, error.status_code, headers=error.headers)
    except Exception:
        logger.exception("request failed id=%s", request_id)
        response = JSONResponse({"detail": "Internal server error"}, status_code=500)
    if mutation and request.url.path != "/api/auth/login":
        try:
            await run_in_threadpool(security.audit, principal.username if principal else "anonymous", request.method, request.url.path, response.status_code, {"request_id": request_id})
        except Exception:
            logger.exception("audit write failed id=%s", request_id)
            response = JSONResponse({"detail": "Audit recording failed; the operation may have completed. Check its state before retrying."}, status_code=503)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    logger.info("request id=%s method=%s path=%s status=%s duration_ms=%.2f", request_id, request.method, request.url.path, response.status_code, (time.monotonic() - started) * 1000)
    return response


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/session")
def session() -> dict:
    return {
        "session_id": "SNF-DEMO-042",
        "source": "Scripted illustration / not trained inference",
        "mode": "scripted_demo",
        "measured_result": False,
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
        "checkpoint_sha256": inference_service.checkpoint_sha256,
        "claims_allowed": False,
        "calibration": "per_horizon_temperature_scaling",
        "ood_rejection": "ready" if inference_service.ood_threshold is not None else "unavailable",
    }


@app.get("/api/ready")
def readiness():
    checks = {"model": inference_service.available,
              "ood": inference_service.ood_threshold is not None,
              "lab_plan": (ROOT / "datasets/controlled_lab_capture_plan.json").is_file(),
              "evidence": (ROOT / "models/cic2018-multiday-lstm/evaluation-summary.json").is_file()}
    try:
        checks["audit_integrity"] = security.audit_health()["valid"]
        with security._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE users SET enabled=enabled WHERE 0")
            db.rollback()
        checks["database"] = True
    except sqlite3.Error:
        checks["database"] = False
    ready = all(checks.values())
    return JSONResponse({"status": "ready" if ready else "not_ready", "checks": checks,
                         "claims_allowed": False, "operating_mode": "research_shadow_mode",
                         "checkpoint_sha256": inference_service.checkpoint_sha256}, status_code=200 if ready else 503)


class CaptureEvaluationRequest(BaseModel):
    report: dict[str, Any]
    labels: dict[str, Any]


@app.post("/api/evaluate-capture")
def evaluate_capture_report(body: CaptureEvaluationRequest, request: Request) -> dict:
    _principal(request, "operator")
    try:
        return evaluate_capture(body.report, body.labels)
    except (ValueError, TypeError, KeyError) as error:
        raise HTTPException(422, str(error)) from error


@app.get("/api/evidence")
def evidence() -> dict:
    summary_path = ROOT / "models" / "cic2018-multiday-lstm" / "evaluation-summary.json"
    result = json.loads(summary_path.read_text(encoding="utf-8"))
    result["early_warning"]["status"] = "legacy_timing_superseded"
    studies = ROOT / "docs/release-evidence/demo-model-studies.json"
    if studies.is_file():
        result["offline_studies"] = json.loads(studies.read_text(encoding="utf-8"))
    return result


@app.get("/api/lab-plan")
def lab_plan() -> dict:
    plan_path = ROOT / "datasets" / "controlled_lab_capture_plan.json"
    return json.loads(plan_path.read_text(encoding="utf-8"))


@app.get("/api/calibration/profiles")
def calibration_profiles(request: Request) -> list[dict]:
    _principal(request, "viewer")
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
    _principal(request, "admin")
    if not inference_service.available:
        raise HTTPException(503, "Model unavailable")
    if calibration_lock.locked():
        raise HTTPException(409, "A calibration job is already running")
    domain = domain.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", domain):
        raise HTTPException(status_code=422, detail="Profile name must be 2-40 lowercase letters, numbers or hyphens")
    if domain in inference_service.domain_calibrations:
        raise HTTPException(status_code=409, detail="A calibration profile with this name already exists")
    if len(benign_files) + len(attack_files) > 16:
        raise HTTPException(413, "Calibration accepts at most 16 files")
    if not benign_files or not attack_files:
        raise HTTPException(status_code=422, detail="Provide at least one benign and one attack PCAP")
    with tempfile.TemporaryDirectory(prefix="calibration-", dir=settings.data_dir) as directory:
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
            output = settings.data_dir / "calibrations" / f"{domain}.json"
            async with calibration_lock:
                if domain in inference_service.domain_calibrations:
                    raise HTTPException(409, "A calibration profile with this name already exists")
                profile = await run_in_threadpool(fit_pcap_domain_calibration, inference_service.checkpoint_path, saved["benign"], saved["attack"], domain, output)
                inference_service.validate_calibration(profile)
                inference_service.domain_calibrations[domain] = profile
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    return profile


@app.post("/api/auth/login")
def login(request: LoginRequest, http_request: Request) -> dict:
    client = http_request.client.host if http_request.client else "unknown"
    if not security.allow_login(client, request.username):
        raise HTTPException(429, "Too many login attempts. Try again later.", headers={"Retry-After": "300"})
    token = security.authenticate(request.username, request.password)
    if token is None:
        security.audit(request.username, "LOGIN", "/api/auth/login", 401)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    principal = security.verify_token(token)
    security.audit(request.username, "LOGIN", "/api/auth/login", 200)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600, "role": principal.role}


@app.post("/api/auth/logout")
def logout(request: Request) -> dict:
    principal = _principal(request, "viewer")
    security.revoke_tokens(principal.username)
    return {"revoked": True}


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
    except sqlite3.IntegrityError as error:
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
    if not inference_service.available:
        raise HTTPException(503, "Model unavailable")
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
        return telemetry.status(stream_id)
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
    _principal(request, "admin")
    allowed = {item.strip() for item in os.getenv("SHADOWNET_KAFKA_BROKERS", "").split(",") if item.strip()}
    requested = {item.strip() for item in body.bootstrap_servers.split(",") if item.strip()}
    if not requested or not requested.issubset(allowed):
        raise HTTPException(403, "Kafka brokers must be explicitly allowed by deployment configuration")
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
    window_seconds: int = Query(5, ge=5, le=5),
    calibration_domain: Optional[str] = Query(None),
) -> dict:
    _principal(request, "operator")
    if calibration_domain and calibration_domain not in inference_service.domain_calibrations:
        raise HTTPException(status_code=422, detail=f"Unknown calibration domain: {calibration_domain}")
    if not inference_service.available:
        raise HTTPException(503, "Model unavailable")
    suffix = Path(file.filename or "capture.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=415, detail="Only .pcap and .pcapng files are accepted.")
    destination = replays.allocate_path(suffix)
    size = 0
    import hashlib
    capture_hash = hashlib.sha256()
    try:
        with destination.open("wb") as stream:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_PCAP_BYTES:
                    raise HTTPException(status_code=413, detail="PCAP exceeds the 250 MB prototype limit.")
                capture_hash.update(chunk)
                stream.write(chunk)
        replay_id, handle = replays.create(destination, file.filename or destination.name, window_seconds, calibration_domain)
    except (ValueError, Scapy_Exception, EOFError) as error:
        destination.unlink(missing_ok=True)
        if isinstance(error, CapacityError):
            raise
        raise HTTPException(422, "Invalid or unsupported PCAP capture") from error
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return {"replay_id": replay_id, "filename": handle.original_name, "size_bytes": size,
            "calibration_domain": calibration_domain or "global",
            "capture_sha256": capture_hash.hexdigest(), "checkpoint_sha256": inference_service.checkpoint_sha256,
            **handle.replay.status()}


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
        return replays.get(replay_id).status()
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
    await websocket.accept()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        if len(raw) > 8192:
            await websocket.close(code=1009)
            return
        authentication = json.loads(raw)
        token = authentication.get("token", "") if isinstance(authentication, dict) else ""
        principal = await run_in_threadpool(security.verify_token, token)
        if not isinstance(authentication, dict) or authentication.get("type") != "auth" or principal is None:
            await websocket.close(code=4401, reason="Valid token required")
            return
        if ROLE_LEVEL[principal.role] < ROLE_LEVEL["operator"]:
            await websocket.close(code=4403, reason="Operator role required")
            return
        handle = await run_in_threadpool(replays.get, replay_id)
        status = await run_in_threadpool(handle.status)
        await websocket.send_json({"type": "connected", "replay_id": replay_id, **status})
        while True:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=60)
            if len(raw) > 8192:
                await websocket.close(code=1009)
                return
            principal = await run_in_threadpool(security.verify_token, token)
            if principal is None:
                await websocket.close(code=4401, reason="Session expired or revoked")
                return
            try:
                message = json.loads(raw)
                if isinstance(message, dict) and message.get("type") == "ping":
                    await run_in_threadpool(handle.status)
                    await websocket.send_json({"type": "pong"})
                    continue
                body = AdvanceRequest.model_validate_json(raw)
                result = await run_in_threadpool(handle.advance, body.seconds)
            except ValueError:
                await websocket.send_json({"type": "error", "detail": "Invalid advance. Seconds must be finite and between 0 and 60."})
                continue
            await run_in_threadpool(security.audit, principal.username, "WS_ADVANCE", f"/ws/replays/{replay_id}", 200)
            await websocket.send_json({"type": "replay_update", **result})
            if result["complete"]:
                await websocket.close(code=1000, reason="Replay complete")
                return
    except KeyError:
        await websocket.close(code=4404, reason="Replay session not found")
    except (asyncio.TimeoutError, ValueError):
        await websocket.close(code=4400, reason="Invalid or timed-out message")
    except WebSocketDisconnect:
        return
