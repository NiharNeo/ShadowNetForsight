from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import numpy as np
from scapy.all import IP, IPv6, TCP, UDP, PcapReader

from pipeline.build_dataset import FEATURES


@dataclass(frozen=True)
class PacketSummary:
    timestamp: float
    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    syn: int
    ack: int
    rst: int
    psh: int
    fin: int
    urg: int
    ttl: int
    tcp_window: int
    fragmented: int
    payload_size: int
    sequence: int


@dataclass
class FlowStats:
    first_timestamp: float
    last_timestamp: float
    origin: tuple[str, int]
    forward_packets: int = 0
    backward_packets: int = 0


@dataclass
class WindowAccumulator:
    start: float
    packet_count: int = 0
    byte_count: int = 0
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    protocols: set[int] = field(default_factory=set)
    flows: dict[tuple, FlowStats] = field(default_factory=dict)
    iats: list[float] = field(default_factory=list)
    last_packet_timestamp: float | None = None
    syn: int = 0
    ack: int = 0
    rst: int = 0
    psh: int = 0
    fin: int = 0
    urg: int = 0
    ttls: list[int] = field(default_factory=list)
    tcp_windows: list[int] = field(default_factory=list)
    payload_sizes: list[int] = field(default_factory=list)
    fragment_count: int = 0
    retransmission_count: int = 0
    seen_sequences: set[tuple[str, str, int, int, int]] = field(default_factory=set)
    port_history: dict[str, list[int]] = field(default_factory=dict)
    directed_edges: set[tuple[str, str]] = field(default_factory=set)
    source_destinations: dict[str, set[str]] = field(default_factory=dict)
    destination_sources: dict[str, set[str]] = field(default_factory=dict)
    east_west_count: int = 0
    identities: dict[str, set[str]] = field(default_factory=dict)
    failed_auth_count: int = 0

    def add(self, packet: PacketSummary) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
        self.src_ips.add(packet.src)
        self.dst_ips.add(packet.dst)
        self.dst_ports.add(packet.dst_port)
        self.protocols.add(packet.protocol)
        self.syn += packet.syn
        self.ack += packet.ack
        self.rst += packet.rst
        self.psh += packet.psh
        self.fin += packet.fin; self.urg += packet.urg
        self.ttls.append(packet.ttl); self.tcp_windows.append(packet.tcp_window); self.payload_sizes.append(packet.payload_size)
        self.fragment_count += packet.fragmented
        sequence_key = (packet.src, packet.dst, packet.src_port, packet.dst_port, packet.sequence)
        self.retransmission_count += int(packet.sequence > 0 and sequence_key in self.seen_sequences)
        self.seen_sequences.add(sequence_key)
        self.port_history.setdefault(packet.src, []).append(packet.dst_port)
        self._add_graph(packet.src, packet.dst, None, None)
        if self.last_packet_timestamp is not None:
            self.iats.append(max(packet.timestamp - self.last_packet_timestamp, 0.0))
        self.last_packet_timestamp = packet.timestamp

        endpoint_a = (packet.src, packet.src_port)
        endpoint_b = (packet.dst, packet.dst_port)
        key = (*sorted((endpoint_a, endpoint_b)), packet.protocol)
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowStats(packet.timestamp, packet.timestamp, endpoint_a)
            self.flows[key] = flow
        flow.last_timestamp = packet.timestamp
        if endpoint_a == flow.origin:
            flow.forward_packets += 1
        else:
            flow.backward_packets += 1

    def add_flow(
        self,
        *,
        timestamp: float,
        src: str,
        dst: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        packets: int,
        bytes_count: int,
        duration: float = 0.0,
        syn: int = 0,
        ack: int = 0,
        rst: int = 0,
        psh: int = 0,
        identity: str | None = None,
        outcome: str | None = None,
    ) -> None:
        """Add an aggregated flow while preserving the PCAP feature contract."""
        packets = max(int(packets), 1)
        self.packet_count += packets
        self.byte_count += max(int(bytes_count), 0)
        self.src_ips.add(src)
        self.dst_ips.add(dst)
        self.dst_ports.add(int(dst_port))
        self.protocols.add(int(protocol))
        self.syn += max(int(syn), 0)
        self.ack += max(int(ack), 0)
        self.rst += max(int(rst), 0)
        self.psh += max(int(psh), 0)
        self._add_graph(src, dst, identity, outcome)
        if self.last_packet_timestamp is not None:
            self.iats.append(max(timestamp - self.last_packet_timestamp, 0.0))
        self.last_packet_timestamp = timestamp
        endpoint_a = (src, int(src_port))
        endpoint_b = (dst, int(dst_port))
        key = (*sorted((endpoint_a, endpoint_b)), int(protocol))
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowStats(timestamp - max(float(duration), 0.0), timestamp, endpoint_a)
            self.flows[key] = flow
        flow.last_timestamp = max(flow.last_timestamp, timestamp)
        flow.forward_packets += packets

    @staticmethod
    def _private(address: str) -> bool:
        return address.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                                   "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))

    def _add_graph(self, src: str, dst: str, identity: str | None, outcome: str | None) -> None:
        self.directed_edges.add((src, dst))
        self.source_destinations.setdefault(src, set()).add(dst)
        self.destination_sources.setdefault(dst, set()).add(src)
        self.east_west_count += int(self._private(src) and self._private(dst))
        if identity:
            self.identities.setdefault(identity, set()).add(src)
        self.failed_auth_count += int(outcome == "failure")

    def as_state(self) -> dict[str, float]:
        durations = [flow.last_timestamp - flow.first_timestamp for flow in self.flows.values()]
        fwd = sum(flow.forward_packets for flow in self.flows.values())
        bwd = sum(flow.backward_packets for flow in self.flows.values())
        values = {
            "flow_count": float(len(self.flows)),
            "unique_src_ips": float(len(self.src_ips)),
            "unique_dst_ips": float(len(self.dst_ips)),
            "unique_dst_ports": float(len(self.dst_ports)),
            "protocol_count": float(len(self.protocols)),
            "duration_mean": float(sum(durations) / len(durations)) if durations else 0.0,
            "fwd_packets_sum": float(fwd),
            "bwd_packets_sum": float(bwd),
            "bytes_sum": float(self.byte_count),
            "iat_mean": float(sum(self.iats) / len(self.iats)) if self.iats else 0.0,
            "syn_count": float(self.syn),
            "ack_count": float(self.ack),
            "rst_count": float(self.rst),
            "psh_count": float(self.psh),
            "syn_ack_ratio": float(self.syn / max(self.ack, 1)),
            "unique_host_edges": float(len(self.directed_edges)),
            "max_source_fanout": float(max((len(peers) for peers in self.source_destinations.values()), default=0)),
            "max_destination_fanin": float(max((len(peers) for peers in self.destination_sources.values()), default=0)),
            "east_west_ratio": float(self.east_west_count / max(self.packet_count, 1)),
            "failed_auth_count": float(self.failed_auth_count),
            "identity_reuse_count": float(sum(len(sources) > 1 for sources in self.identities.values())),
            "fin_count": float(self.fin), "urg_count": float(self.urg),
            "ttl_mean": float(sum(self.ttls) / len(self.ttls)) if self.ttls else 0.0,
            "ttl_variance": float(np.var(self.ttls)) if self.ttls else 0.0,
            "tcp_window_mean": float(sum(self.tcp_windows) / len(self.tcp_windows)) if self.tcp_windows else 0.0,
            "fragment_count": float(self.fragment_count),
            "payload_size_mean": float(sum(self.payload_sizes) / len(self.payload_sizes)) if self.payload_sizes else 0.0,
            "payload_size_std": float(np.std(self.payload_sizes)) if self.payload_sizes else 0.0,
            "retransmission_count": float(self.retransmission_count),
            "sequential_port_ratio": float(sum(abs(b-a) == 1 for ports in self.port_history.values() for a,b in zip(ports, ports[1:])) / max(sum(max(len(p)-1, 0) for p in self.port_history.values()), 1)),
        }
        return {feature: values[feature] for feature in FEATURES}


def summarize(packet) -> PacketSummary | None:
    network = packet.getlayer(IP) or packet.getlayer(IPv6)
    if network is None:
        return None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    src_port = int(getattr(transport, "sport", 0))
    dst_port = int(getattr(transport, "dport", 0))
    flags = int(getattr(transport, "flags", 0)) if isinstance(transport, TCP) else 0
    return PacketSummary(
        timestamp=float(packet.time),
        src=str(network.src),
        dst=str(network.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=int(getattr(network, "proto", getattr(network, "nh", 0))),
        length=len(packet),
        syn=int(bool(flags & 0x02)),
        ack=int(bool(flags & 0x10)),
        rst=int(bool(flags & 0x04)),
        psh=int(bool(flags & 0x08)),
        fin=int(bool(flags & 0x01)), urg=int(bool(flags & 0x20)),
        ttl=int(getattr(network, "ttl", getattr(network, "hlim", 0))),
        tcp_window=int(getattr(transport, "window", 0)) if isinstance(transport, TCP) else 0,
        fragmented=int(bool(getattr(network, "frag", 0)) or bool(int(getattr(network, "flags", 0)) & 1)),
        payload_size=len(bytes(transport.payload)) if transport is not None else 0,
        sequence=int(getattr(transport, "seq", 0)) if isinstance(transport, TCP) else 0,
    )


class StreamingPcapReplay:
    """Incremental PCAP reader whose emitted states never include future packets."""

    def __init__(self, path: Path, window_seconds: int = 5) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.path = path
        self.window_seconds = window_seconds
        self._reader = PcapReader(str(path))
        self._packets = self._summaries()
        self._next = next(self._packets, None)
        if self._next is None:
            self._reader.close()
            raise ValueError("PCAP contains no IPv4 or IPv6 packets.")
        self.capture_start = self._next.timestamp
        self.current_time = self.capture_start
        self.processed_packets = 0
        self.complete = False
        self._windows: dict[int, WindowAccumulator] = {}
        self._emitted_through = -1

    def _summaries(self) -> Iterator[PacketSummary]:
        for packet in self._reader:
            summary = summarize(packet)
            if summary is not None:
                yield summary

    def _window_index(self, timestamp: float) -> int:
        return max(int((timestamp - self.capture_start) // self.window_seconds), 0)

    def advance(self, seconds: float) -> dict:
        if seconds <= 0:
            raise ValueError("advance seconds must be positive")
        cutoff = self.current_time + seconds
        consumed = 0
        while self._next is not None and self._next.timestamp <= cutoff:
            index = self._window_index(self._next.timestamp)
            accumulator = self._windows.setdefault(index, WindowAccumulator(self.capture_start + index * self.window_seconds))
            accumulator.add(self._next)
            self.processed_packets += 1
            consumed += 1
            self._next = next(self._packets, None)
        self.current_time = cutoff
        if self._next is None:
            self.complete = True
            self._reader.close()

        last_closed = int((self.current_time - self.capture_start) // self.window_seconds) - 1
        emitted = []
        for index in range(self._emitted_through + 1, last_closed + 1):
            accumulator = self._windows.pop(index, WindowAccumulator(self.capture_start + index * self.window_seconds))
            emitted.append({
                "window_index": index,
                "window_start": accumulator.start,
                "window_end": accumulator.start + self.window_seconds,
                "packet_count": accumulator.packet_count,
                "features": accumulator.as_state(),
            })
            self._emitted_through = index
        return {
            "simulated_time": self.current_time,
            "elapsed_seconds": self.current_time - self.capture_start,
            "packets_consumed": consumed,
            "processed_packets": self.processed_packets,
            "complete": self.complete,
            "states": emitted,
        }

    def status(self) -> dict:
        return {
            "capture_start": self.capture_start,
            "simulated_time": self.current_time,
            "elapsed_seconds": self.current_time - self.capture_start,
            "processed_packets": self.processed_packets,
            "complete": self.complete,
            "window_seconds": self.window_seconds,
        }

    def close(self) -> None:
        self._reader.close()
        self.complete = True
