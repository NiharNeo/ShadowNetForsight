from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Iterable

from pipeline.pcap_replay import WindowAccumulator


def _timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return datetime.now(timezone.utc).timestamp()
    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text).timestamp()


def _integer(record: dict[str, Any], *names: str, default: int = 0) -> int:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return int(float(record[name]))
    return default


@dataclass(frozen=True)
class TelemetryEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6
    packets: int = 1
    bytes_count: int = 0
    duration: float = 0.0
    syn: int = 0
    ack: int = 0
    rst: int = 0
    psh: int = 0
    source: str = "unknown"
    event_type: str = "flow"
    identity: str | None = None
    outcome: str | None = None


def adapt_netflow(record: dict[str, Any], source: str = "netflow") -> TelemetryEvent:
    """Normalize common NetFlow v5/v9 and IPFIX field aliases."""
    protocol = record.get("protocolIdentifier", record.get("PROTOCOL", record.get("protocol", 6)))
    if isinstance(protocol, str) and not protocol.isdigit():
        protocol = {"tcp": 6, "udp": 17, "icmp": 1}.get(protocol.lower(), 0)
    flags = _integer(record, "tcpControlBits", "TCP_FLAGS", "tcp_flags")
    return TelemetryEvent(
        timestamp=_timestamp(record.get("flowEndMilliseconds", record.get("LAST_SWITCHED", record.get("timestamp")))),
        src_ip=str(record.get("sourceIPv4Address", record.get("IPV4_SRC_ADDR", record.get("src_ip", "unknown")))),
        dst_ip=str(record.get("destinationIPv4Address", record.get("IPV4_DST_ADDR", record.get("dst_ip", "unknown")))),
        src_port=_integer(record, "sourceTransportPort", "L4_SRC_PORT", "src_port"),
        dst_port=_integer(record, "destinationTransportPort", "L4_DST_PORT", "dst_port"),
        protocol=int(protocol),
        packets=max(_integer(record, "packetDeltaCount", "IN_PKTS", "packets", default=1), 1),
        bytes_count=_integer(record, "octetDeltaCount", "IN_BYTES", "bytes"),
        duration=float(record.get("duration", 0.0)),
        syn=int(bool(flags & 0x02)), ack=int(bool(flags & 0x10)),
        rst=int(bool(flags & 0x04)), psh=int(bool(flags & 0x08)),
        source=source,
    )


def adapt_cowrie(record: dict[str, Any]) -> TelemetryEvent:
    # Native Cowrie uses eventid/src_ip/dst_ip. The SRDS 2025 public capture
    # sample uses alert/src_host/dst_host while retaining Cowrie provenance.
    event_id = str(record.get("eventid", record.get("alert", "cowrie.event")))
    success = event_id == "cowrie.login.success"
    return TelemetryEvent(
        timestamp=_timestamp(record.get("timestamp")),
        src_ip=str(record.get("src_ip", record.get("src_host", "unknown"))),
        dst_ip=str(record.get("dst_ip", record.get("dst_host", record.get("sensor", "honeypot")))),
        src_port=_integer(record, "src_port"),
        dst_port=_integer(record, "dst_port", default=22),
        protocol=6,
        packets=1,
        bytes_count=len(str(record.get("message", record.get("info", ""))).encode()),
        syn=1 if event_id == "cowrie.session.connect" else 0,
        ack=1 if success else 0,
        source="cowrie",
        event_type=event_id,
        identity=str(record["username"]) if "username" in record else None,
        outcome="success" if success else ("failure" if event_id == "cowrie.login.failed" else None),
    )


def adapt_message(payload: str | bytes | dict[str, Any], source: str = "auto") -> TelemetryEvent:
    record = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
    if not isinstance(record, dict):
        raise ValueError("Telemetry message must be a JSON object")
    detected = "cowrie" if str(record.get("eventid", "")).startswith("cowrie.") or "pot_id" in record else "netflow"
    kind = detected if source in ("auto", "kafka") else source
    event = adapt_cowrie(record) if kind == "cowrie" else adapt_netflow(record, "kafka" if source == "kafka" else kind)
    return event


class StreamingTelemetry:
    """Event-time telemetry windowing with bounded lateness and no future leakage."""

    def __init__(self, window_seconds: int = 5, allowed_lateness: float = 2.0) -> None:
        if window_seconds <= 0 or allowed_lateness < 0:
            raise ValueError("window_seconds must be positive and allowed_lateness non-negative")
        self.window_seconds = window_seconds
        self.allowed_lateness = allowed_lateness
        self.origin: float | None = None
        self.max_timestamp: float | None = None
        self.emitted_through = -1
        self.windows: dict[int, WindowAccumulator] = {}
        self.accepted = 0
        self.rejected_late = 0

    def ingest(self, events: Iterable[TelemetryEvent], flush: bool = False) -> dict[str, Any]:
        accepted_now = 0
        for event in sorted(events, key=lambda item: item.timestamp):
            if self.origin is None:
                self.origin = event.timestamp
            index = max(int((event.timestamp - self.origin) // self.window_seconds), 0)
            if index <= self.emitted_through:
                self.rejected_late += 1
                continue
            accumulator = self.windows.setdefault(index, WindowAccumulator(self.origin + index * self.window_seconds))
            accumulator.add_flow(timestamp=event.timestamp, src=event.src_ip, dst=event.dst_ip,
                                 src_port=event.src_port, dst_port=event.dst_port, protocol=event.protocol,
                                 packets=event.packets, bytes_count=event.bytes_count, duration=event.duration,
                                 syn=event.syn, ack=event.ack, rst=event.rst, psh=event.psh,
                                 identity=event.identity, outcome=event.outcome)
            self.max_timestamp = event.timestamp if self.max_timestamp is None else max(self.max_timestamp, event.timestamp)
            self.accepted += 1
            accepted_now += 1
        states: list[dict[str, Any]] = []
        if self.origin is not None and self.max_timestamp is not None:
            watermark = self.max_timestamp + self.window_seconds if flush else self.max_timestamp - self.allowed_lateness
            last_closed = int((watermark - self.origin) // self.window_seconds) - 1
            for index in range(self.emitted_through + 1, last_closed + 1):
                accumulator = self.windows.pop(index, WindowAccumulator(self.origin + index * self.window_seconds))
                states.append({"window_index": index, "window_start": accumulator.start,
                               "window_end": accumulator.start + self.window_seconds,
                               "packet_count": accumulator.packet_count, "features": accumulator.as_state()})
                self.emitted_through = index
        return {"events_accepted": accepted_now, "events_accepted_total": self.accepted,
                "events_rejected_late": self.rejected_late, "states": states, "status": self.status()}

    def status(self) -> dict[str, Any]:
        return {"window_seconds": self.window_seconds, "allowed_lateness": self.allowed_lateness,
                "events_accepted": self.accepted, "events_rejected_late": self.rejected_late,
                "pending_windows": len(self.windows), "max_timestamp": self.max_timestamp}
