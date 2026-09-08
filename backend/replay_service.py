from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from pipeline.pcap_replay import StreamingPcapReplay
from backend.inference_service import LSTMInferenceService, ReplayInferenceSession


@dataclass
class ReplayHandle:
    replay: StreamingPcapReplay
    inference: ReplayInferenceSession
    path: Path
    original_name: str

    def advance(self, seconds: float) -> dict:
        result = self.replay.advance(seconds)
        result["inference"] = self.inference.ingest(result["states"])
        return result


class ReplayRegistry:
    def __init__(self, upload_dir: Path, inference_service: LSTMInferenceService) -> None:
        self.upload_dir = upload_dir
        self.inference_service = inference_service
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, ReplayHandle] = {}

    def create(self, path: Path, original_name: str, window_seconds: int, calibration_domain: str | None = None) -> tuple[str, ReplayHandle]:
        replay_id = uuid4().hex
        handle = ReplayHandle(StreamingPcapReplay(path, window_seconds), ReplayInferenceSession(self.inference_service, calibration_domain), path, original_name)
        self._sessions[replay_id] = handle
        return replay_id, handle

    def get(self, replay_id: str) -> ReplayHandle:
        try:
            return self._sessions[replay_id]
        except KeyError as error:
            raise KeyError(f"Replay session not found: {replay_id}") from error

    def remove(self, replay_id: str) -> None:
        handle = self.get(replay_id)
        handle.replay.close()
        handle.path.unlink(missing_ok=True)
        del self._sessions[replay_id]

    def allocate_path(self, suffix: str) -> Path:
        return self.upload_dir / f"{uuid4().hex}{suffix}"
