from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock, Event, Thread
import logging
import time
from backend.replay_service import CapacityError
from backend.kafka_config import consumer_security
from typing import Any
from uuid import uuid4

from backend.inference_service import LSTMInferenceService, ReplayInferenceSession
from pipeline.feature_contract import TELEMETRY_CONTRACT
from pipeline.telemetry import StreamingTelemetry, adapt_message
from pipeline.host_graph import HostGraphTracker


@dataclass
class TelemetryHandle:
    stream: StreamingTelemetry
    inference: ReplayInferenceSession
    source: str
    graph: HostGraphTracker

    lock: RLock = field(default_factory=RLock)
    last_used: float = field(default_factory=time.monotonic)
    closed: bool = False

    def ingest(self, records: list[dict[str, Any]], flush: bool = False) -> dict[str, Any]:
        events = [adapt_message(record, self.source) for record in records]
        return self.ingest_events(events, flush)

    def ingest_events(self, events, flush=False):
        events = list(events)
        with self.lock:
            if self.closed:
                raise KeyError("Telemetry session closed")
            # Windowing rejects previously closed windows. Keep contextual evidence
            # on the identical event boundary, including batches supplied as generators.
            accepted = [event for event in events if self.stream.origin is None or
                        int((event.timestamp - self.stream.origin) // self.stream.window_seconds) > self.stream.emitted_through]
            result = self.stream.ingest(events, flush=flush)
            self.graph.update(accepted)
            self.last_used = time.monotonic()
            result["inference"] = self.inference.ingest(result["states"])
            result["host_graph"] = self.graph.features()
            return result


    def status(self) -> dict:
        with self.lock:
            if self.closed:
                raise KeyError("Telemetry session closed")
            return {"source": self.source, **self.stream.status(),
                    "calibration_domain": self.inference.domain or "global",
                    "warmup_states": len(self.inference.states),
                    "required_states": self.inference.service.sequence_length,
                    "host_graph": self.graph.features()}



class TelemetryRegistry:
    def __init__(self, inference_service: LSTMInferenceService, max_sessions: int = 32, ttl: int = 1800) -> None:
        self.inference_service = inference_service
        self._streams: dict[str, TelemetryHandle] = {}
        self._lock = RLock()
        self.max_sessions, self.ttl = max_sessions, ttl
        self._bridges: dict[str, KafkaBridge] = {}

    def create(self, source: str, window_seconds: int, allowed_lateness: float, calibration_domain: str | None = None) -> tuple[str, TelemetryHandle]:
        stream_id = uuid4().hex
        handle = TelemetryHandle(StreamingTelemetry(window_seconds, allowed_lateness), ReplayInferenceSession(self.inference_service, calibration_domain, input_contract=TELEMETRY_CONTRACT), source, HostGraphTracker())
        with self._lock:
            self.cleanup()
            if len(self._streams) >= self.max_sessions:
                raise CapacityError("Telemetry capacity reached. Close an existing stream.")
            self._streams[stream_id] = handle
        return stream_id, handle

    def get(self, stream_id: str) -> TelemetryHandle:
        with self._lock:
            self.cleanup()
            handle = self._streams.get(stream_id)
        if handle is None:
            raise KeyError(f"Telemetry stream not found: {stream_id}")
        return handle

    def cleanup(self) -> None:
        with self._lock:
            for key, handle in list(self._streams.items()):
                if time.monotonic() - handle.last_used > self.ttl:
                    self.remove(key)

    def close(self) -> None:
        with self._lock:
            for key in list(self._streams):
                self.remove(key)

    def remove(self, stream_id: str) -> None:
        with self._lock:
            handle = self._streams.pop(stream_id, None)
            if handle is None:
                raise KeyError("Telemetry stream not found")
            with handle.lock:
                handle.closed = True
            bridge = self._bridges.pop(stream_id, None)
            if bridge:
                bridge.close()

    def connect_kafka(self, stream_id: str, bootstrap_servers: str, topic: str, group_id: str) -> None:
        with self._lock:
            handle = self.get(stream_id)
            if stream_id in self._bridges:
                raise ValueError("Kafka bridge already connected for this stream")
            bridge = KafkaBridge(handle, bootstrap_servers, topic, group_id)
            self._bridges[stream_id] = bridge
            try:
                bridge.start()
            except Exception:
                self._bridges.pop(stream_id, None)
                bridge.close()
                raise

    def status(self, stream_id: str) -> dict:
        with self._lock:
            handle = self.get(stream_id)
            bridge = self._bridges.get(stream_id)
            kafka = bridge.status() if bridge else {"state": "disconnected", "connected": False, "error_type": None}
            return {**handle.status(), "kafka": kafka}

    def kafka_connected(self, stream_id: str) -> bool:
        with self._lock:
            bridge = self._bridges.get(stream_id)
            return bool(bridge and bridge.status()["connected"])


class KafkaBridge:
    """Optional real Kafka consumer; kafka-python is loaded only when configured."""

    def __init__(self, handle: TelemetryHandle, bootstrap_servers: str, topic: str, group_id: str) -> None:
        try:
            from kafka import KafkaConsumer
        except ImportError as error:
            raise RuntimeError("Install kafka-python to enable broker consumption") from error
        self.stop_event = Event()
        self._state_lock = RLock()
        self.state = "starting"
        self.error_type = None
        self._consumer_closed = False
        security_options = consumer_security()
        self.consumer = KafkaConsumer(topic, bootstrap_servers=bootstrap_servers, group_id=group_id,
                                      auto_offset_reset="latest", enable_auto_commit=False,
                                      api_version_auto_timeout_ms=3000, max_partition_fetch_bytes=1048576,
                                      value_deserializer=lambda value: value.decode("utf-8"), **security_options)
        self.handle = handle
        self.thread = Thread(target=self._run, daemon=True, name=f"kafka-{topic}")

    def start(self) -> None:
        self.thread.start()

    def status(self) -> dict:
        with self._state_lock:
            return {"state": self.state, "connected": self.state == "running" and self.thread.is_alive(),
                    "error_type": self.error_type}

    def _close_consumer(self) -> None:
        with self._state_lock:
            if self._consumer_closed:
                return
            self._consumer_closed = True
        self.consumer.close()

    def _run(self) -> None:
        with self._state_lock:
            self.state = "running"
        try:
            while not self.stop_event.is_set():
                batch = self.consumer.poll(timeout_ms=1000, max_records=500)
                records = [adapt_message(message.value, "kafka") for messages in batch.values() for message in messages]
                if records:
                    self.handle.ingest_events(records)
                    self.consumer.commit()
        except Exception as error:
            with self._state_lock:
                self.state = "failed"
                self.error_type = type(error).__name__
            logging.getLogger(__name__).exception("Kafka ingestion stopped")
        finally:
            self.stop_event.set()
            try:
                self._close_consumer()
            finally:
                with self._state_lock:
                    if self.state != "failed":
                        self.state = "stopped"

    def close(self) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        else:
            self._close_consumer()
