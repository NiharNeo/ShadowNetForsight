from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, RLock
from time import time
from typing import Any
from uuid import uuid4

from backend.telemetry_service import TelemetryHandle, TelemetryRegistry


LAB_SOURCE = "192.0.2.44"
LAB_EDGE = "10.10.0.5"
LAB_DATABASE = "10.10.0.12"

PHASES = (
    ("Baseline", "Normal application and administration traffic is establishing the reference pattern."),
    ("Service discovery", "A controlled lab source is contacting an increasing number of ports."),
    ("Authentication pressure", "Disposable SSH accounts are receiving repeated failed login events."),
    ("Internal pivot", "The scenario is now producing east-west traffic toward the database tier."),
)


@dataclass
class LiveLabSession:
    stream_id: str
    handle: TelemetryHandle
    base_timestamp: float = field(default_factory=time)
    step: int = 0
    total_steps: int = 24
    stopped: bool = False
    lock: RLock = field(default_factory=RLock)

    def _phase(self) -> tuple[int, str, str]:
        phase_index = min(self.step // 6, len(PHASES) - 1)
        name, detail = PHASES[phase_index]
        return phase_index, name, detail

    def _records(self, timestamp: float, phase_index: int) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        if phase_index == 0:
            ports, count = (53, 80, 443), 4
        elif phase_index == 1:
            ports = tuple(range(20, 20 + 3 + (self.step % 6) * 3))
            count = len(ports)
        elif phase_index == 2:
            ports, count = (22,), 8 + (self.step % 6) * 3
        else:
            ports, count = (22, 445, 3389), 10 + (self.step % 6) * 2

        for index in range(count):
            target = LAB_DATABASE if phase_index == 3 and index % 3 else LAB_EDGE
            records.append({
                "timestamp": timestamp + index * 0.01,
                "src_ip": LAB_EDGE if phase_index == 3 and index % 3 else LAB_SOURCE,
                "dst_ip": target,
                "src_port": 40000 + self.step * 100 + index,
                "dst_port": ports[index % len(ports)],
                "protocol": 6,
                "packets": 1 + phase_index,
                "bytes": 96 + phase_index * 48,
                "tcp_flags": 2 if phase_index else 16,
                "duration": 0.02 + phase_index * 0.03,
            })
        if phase_index == 2:
            for index in range(4 + self.step % 6):
                records.append({
                    "eventid": "cowrie.login.failed",
                    "timestamp": timestamp + 0.4 + index * 0.01,
                    "src_ip": LAB_SOURCE,
                    "dst_ip": LAB_EDGE,
                    "username": ("admin", "root", "service")[index % 3],
                })
        return records

    def advance(self) -> dict[str, Any]:
        with self.lock:
            if self.stopped or self.step >= self.total_steps:
                return self.status()
            phase_index, phase, detail = self._phase()
            event_timestamp = self.base_timestamp + self.step * 5
            final_step = self.step == self.total_steps - 1
            result = self.handle.ingest(self._records(event_timestamp, phase_index), flush=final_step)
            self.step += 1
            return {
                "step": self.step,
                "total_steps": self.total_steps,
                "elapsed_model_seconds": self.step * 5,
                "phase": phase,
                "detail": detail,
                "complete": self.step >= self.total_steps,
                "safety": "Synthetic telemetry only; no packets are sent to a network target.",
                **result,
            }

    def status(self) -> dict[str, Any]:
        _, phase, detail = self._phase()
        return {
            "step": self.step,
            "total_steps": self.total_steps,
            "elapsed_model_seconds": self.step * 5,
            "phase": phase,
            "detail": detail,
            "complete": self.stopped or self.step >= self.total_steps,
            "safety": "Synthetic telemetry only; no packets are sent to a network target.",
        }

    def stop(self) -> None:
        with self.lock:
            self.stopped = True


class LiveLabRegistry:
    def __init__(self, telemetry: TelemetryRegistry) -> None:
        self.telemetry = telemetry
        self._sessions: dict[str, LiveLabSession] = {}
        self._lock = Lock()

    def create(self) -> tuple[str, LiveLabSession]:
        stream_id, handle = self.telemetry.create("auto", 5, 0)
        session_id = uuid4().hex
        session = LiveLabSession(stream_id=stream_id, handle=handle)
        with self._lock:
            self._sessions[session_id] = session
        return session_id, session

    def get(self, session_id: str) -> LiveLabSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Live lab session not found: {session_id}")
        return session

    def remove(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            raise KeyError(f"Live lab session not found: {session_id}")
        session.stop()
        self.telemetry.remove(session.stream_id)
