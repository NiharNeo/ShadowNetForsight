from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
import time
from uuid import uuid4

from pipeline.pcap_replay import StreamingPcapReplay
from backend.inference_service import LSTMInferenceService, ReplayInferenceSession


class CapacityError(ValueError):
    pass


@dataclass
class ReplayHandle:
    replay: StreamingPcapReplay
    inference: ReplayInferenceSession
    path: Path
    original_name: str
    lock: RLock = field(default_factory=RLock)
    last_used: float = field(default_factory=time.monotonic)
    closed: bool = False

    def advance(self, seconds: float) -> dict:
        with self.lock:
            if self.closed:
                raise KeyError("Replay session closed")
            self.last_used = time.monotonic()
            result = self.replay.advance(seconds)
            result["inference"] = self.inference.ingest(result["states"])
            return result

    def status(self) -> dict:
        with self.lock:
            if self.closed:
                raise KeyError("Replay session closed")
            self.last_used = time.monotonic()
            return self.replay.status()

    def close(self) -> None:
        with self.lock:
            self.closed = True
            self.replay.close()
            self.path.unlink(missing_ok=True)


class ReplayRegistry:
    def __init__(self, upload_dir: Path, inference_service: LSTMInferenceService, max_sessions: int = 32, ttl: int = 1800) -> None:
        self.upload_dir = upload_dir
        self.inference_service = inference_service
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, ReplayHandle] = {}
        self._lock = RLock()
        self.max_sessions, self.ttl = max_sessions, ttl

    def cleanup(self) -> None:
        with self._lock:
            for key, handle in list(self._sessions.items()):
                if time.monotonic() - handle.last_used > self.ttl:
                    handle.close()
                    del self._sessions[key]

    def create(self, path: Path, original_name: str, window_seconds: int, calibration_domain: str | None = None) -> tuple[str, ReplayHandle]:
        with self._lock:
            self.cleanup()
            if len(self._sessions) >= self.max_sessions:
                raise CapacityError("Replay capacity reached. Close an existing replay before uploading.")
            with path.open("rb") as capture:
                magic = capture.read(4)
            if magic not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}:
                raise ValueError("Unsupported PCAP signature")
            replay_id = uuid4().hex
            replay = StreamingPcapReplay(path, window_seconds)
            try:
                handle = ReplayHandle(replay, ReplayInferenceSession(self.inference_service, calibration_domain), path, original_name)
                self._sessions[replay_id] = handle
            except Exception:
                replay.close()
                raise
            return replay_id, handle

    def get(self, replay_id: str) -> ReplayHandle:
        with self._lock:
            self.cleanup()
            if replay_id not in self._sessions:
                raise KeyError("Replay session not found")
            return self._sessions[replay_id]

    def remove(self, replay_id: str) -> None:
        with self._lock:
            handle = self.get(replay_id)
            handle.close()
            del self._sessions[replay_id]

    def close(self) -> None:
        with self._lock:
            for handle in self._sessions.values():
                handle.close()
            self._sessions.clear()

    def allocate_path(self, suffix: str) -> Path:
        return self.upload_dir / f"{uuid4().hex}{suffix}"
