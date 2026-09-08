from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

from pipeline.telemetry import TelemetryEvent


def _private(address: str) -> bool:
    return address.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                               "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                               "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))


@dataclass
class HostGraphTracker:
    """Bounded host/identity graph used as contextual evidence beside the flow model."""

    max_events: int = 50_000
    events: deque[TelemetryEvent] = field(default_factory=deque)

    def update(self, events: Iterable[TelemetryEvent]) -> None:
        self.events.extend(events)
        while len(self.events) > self.max_events:
            self.events.popleft()

    def features(self) -> dict:
        peers: dict[str, set[str]] = defaultdict(set)
        outbound: Counter[str] = Counter()
        identities: dict[str, set[str]] = defaultdict(set)
        failed: Counter[str] = Counter()
        east_west = 0
        for event in self.events:
            peers[event.src_ip].add(event.dst_ip)
            peers[event.dst_ip].add(event.src_ip)
            outbound[event.src_ip] += 1
            if event.identity:
                identities[event.identity].add(event.src_ip)
            if event.outcome == "failure":
                failed[event.src_ip] += 1
            east_west += int(_private(event.src_ip) and _private(event.dst_ip))
        total = max(len(self.events), 1)
        ranked_hosts = sorted(peers, key=lambda host: (len(peers[host]), outbound[host]), reverse=True)[:10]
        return {
            "event_count": len(self.events),
            "host_count": len(peers),
            "east_west_ratio": round(east_west / total, 5),
            "identity_reuse_count": sum(len(sources) > 1 for sources in identities.values()),
            "top_hosts": [
                {"host": host, "peer_count": len(peers[host]), "outbound_events": outbound[host],
                 "failed_authentications": failed[host]}
                for host in ranked_hosts
            ],
            "reused_identities": [identity for identity, sources in identities.items() if len(sources) > 1][:20],
        }
