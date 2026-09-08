from __future__ import annotations

from dataclasses import dataclass
from threading import Lock, Event, Thread
from typing import Any
from uuid import uuid4

from backend.inference_service import LSTMInferenceService, ReplayInferenceSession
from pipeline.telemetry import StreamingTelemetry, adapt_message
from pipeline.host_graph import HostGraphTracker


@dataclass
class TelemetryHandle:
    stream: StreamingTelemetry
    inference: ReplayInferenceSession
    source: str
    graph: HostGraphTracker

    def ingest(self, records: list[dict[str, Any]], flush: bool = False) -> dict[str, Any]:
        events = [adapt_message(record, self.source) for record in records]
        self.graph.update(events)
        result = self.stream.ingest(events, flush=flush)
        result["inference"] = self.inference.ingest(result["states"])
        result["host_graph"] = self.graph.features()
        return result


class TelemetryRegistry:
    def __init__(self, inference_service: LSTMInferenceService) -> None:
        self.inference_service = inference_service
        self._streams: dict[str, TelemetryHandle] = {}
        self._lock = Lock()
        self._bridges: dict[str, KafkaBridge] = {}

    def create(self, source: str, window_seconds: int, allowed_lateness: float, calibration_domain: str | None = None) -> tuple[str, TelemetryHandle]:
        stream_id = uuid4().hex
        handle = TelemetryHandle(StreamingTelemetry(window_seconds, allowed_lateness), ReplayInferenceSession(self.inference_service, calibration_domain), source, HostGraphTracker())
        with self._lock:
            self._streams[stream_id] = handle
        return stream_id, handle

    def get(self, stream_id: str) -> TelemetryHandle:
        with self._lock:
            handle = self._streams.get(stream_id)
        if handle is None:
            raise KeyError(f"Telemetry stream not found: {stream_id}")
        return handle

    def remove(self, stream_id: str) -> None:
        with self._lock:
            bridge = self._bridges.pop(stream_id, None)
            if bridge:
                bridge.close()
            if self._streams.pop(stream_id, None) is None:
                raise KeyError(f"Telemetry stream not found: {stream_id}")

    def connect_kafka(self, stream_id: str, bootstrap_servers: str, topic: str, group_id: str) -> None:
        handle = self.get(stream_id)
        with self._lock:
            if stream_id in self._bridges:
                raise ValueError("Kafka bridge already connected for this stream")
            bridge = KafkaBridge(handle, bootstrap_servers, topic, group_id)
            self._bridges[stream_id] = bridge
        bridge.start()

    def kafka_connected(self, stream_id: str) -> bool:
        with self._lock:
            return stream_id in self._bridges


class KafkaBridge:
    """Optional real Kafka consumer; kafka-python is loaded only when configured."""

    def __init__(self, handle: TelemetryHandle, bootstrap_servers: str, topic: str, group_id: str) -> None:
        try:
            from kafka import KafkaConsumer
        except ImportError as error:
            raise RuntimeError("Install kafka-python to enable broker consumption") from error
        self.stop_event = Event()
        self.consumer = KafkaConsumer(topic, bootstrap_servers=bootstrap_servers, group_id=group_id,
                                      auto_offset_reset="latest", enable_auto_commit=True,
                                      value_deserializer=lambda value: value.decode("utf-8"))
        self.handle = handle
        self.thread = Thread(target=self._run, daemon=True, name=f"kafka-{topic}")

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            batch = self.consumer.poll(timeout_ms=1000, max_records=500)
            records = [adapt_message(message.value, "kafka") for messages in batch.values() for message in messages]
            if records:
                self.handle.graph.update(records)
                result = self.handle.stream.ingest(records)
                self.handle.inference.ingest(result["states"])

    def close(self) -> None:
        self.stop_event.set()
        self.consumer.close()
        self.thread.join(timeout=3)
