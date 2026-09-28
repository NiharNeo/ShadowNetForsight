"""Bounded causal connection context for a future, separately trained detector.

One instance per capture/stream. No labels or future packets are accepted.
This does not change the legacy packet-window feature contract or checkpoint.
"""
from collections import Counter, deque
import math

CONTEXT_CONTRACT='shadownet.connection-context.v1'
CONTEXT_FEATURES=('context_packets','context_destination_endpoints','context_source_hosts',
                  'context_syn_packets','context_syn_destinations','context_syn_connection_keys',
                  'context_repeated_syn_fraction','context_max_syn_destination_share',
                  'context_observed_seconds')

class ConnectionContext:
    def __init__(self, seconds=60, max_packets=100000):
        if not math.isfinite(seconds) or seconds<=0 or not isinstance(max_packets,int) or isinstance(max_packets,bool) or max_packets<1:
            raise ValueError('Context limits must be positive')
        self.seconds=seconds;self.max_packets=max_packets
        self.packets=deque();self.destinations=Counter();self.sources=Counter()
        self.syn_destinations=Counter();self.syn_keys=Counter()
        self.first_time=None;self.clock=None;self.syn_count=0;self.invalid=False

    def _advance(self, timestamp):
        if self.invalid:raise ValueError('Context invalid after packet overflow; create a fresh session')
        if not math.isfinite(timestamp) or (self.clock is not None and timestamp<self.clock):
            raise ValueError('Context timestamps must be finite and chronological')
        self.clock=timestamp
        while self.packets and self.packets[0][0]<=timestamp-self.seconds:
            _,source,destination,syn_key=self.packets.popleft()
            self._remove(self.sources,source);self._remove(self.destinations,destination)
            if syn_key is not None:
                self._remove(self.syn_keys,syn_key);self._remove(self.syn_destinations,destination);self.syn_count-=1

    @staticmethod
    def _remove(counter,key):
        counter[key]-=1
        if counter[key]==0:del counter[key]

    def add(self, packet):
        self._advance(packet.timestamp)
        if len(self.packets)>=self.max_packets:
            self.invalid=True
            raise ValueError('Context packet limit exceeded; do not score truncated context')
        if self.first_time is None:self.first_time=packet.timestamp
        destination=(packet.dst,packet.dst_port,packet.protocol)
        syn_key=(packet.src,packet.src_port,*destination) if packet.protocol==6 and packet.syn and not packet.ack else None
        self.packets.append((packet.timestamp,packet.src,destination,syn_key))
        self.sources[packet.src]+=1;self.destinations[destination]+=1
        if syn_key is not None:
            self.syn_keys[syn_key]+=1;self.syn_destinations[destination]+=1;self.syn_count+=1

    def snapshot(self, timestamp):
        self._advance(timestamp)
        return dict(zip(CONTEXT_FEATURES,(
            len(self.packets),len(self.destinations),len(self.sources),self.syn_count,
            len(self.syn_destinations),len(self.syn_keys),
            (self.syn_count-len(self.syn_keys))/self.syn_count if self.syn_count else 0,
            max(self.syn_destinations.values(),default=0)/self.syn_count if self.syn_count else 0,
            min(self.seconds,max(0,timestamp-self.first_time)) if self.first_time is not None else 0)))


def context_states(path, window_seconds=5, seconds=60, max_packets=100000):
    """Emit context at completed-window boundaries before reading later packets.

    The final partial window is excluded. Trailing context uses (t-seconds,t];
    a packet at the output boundary is assigned to the following window.
    """
    from scapy.all import PcapReader
    from pipeline.pcap_replay import summarize
    if not math.isfinite(window_seconds) or window_seconds<=0:raise ValueError('Invalid window size')
    context=ConnectionContext(seconds,max_packets);origin=None;boundary=None;states=[]
    with PcapReader(str(path)) as reader:
        for raw in reader:
            packet=summarize(raw)
            if packet is None:continue
            if origin is None:
                origin=packet.timestamp;boundary=origin+window_seconds
            if not math.isfinite(packet.timestamp) or packet.timestamp-origin>86400:
                raise ValueError('Context capture timestamp invalid or exceeds 24 hours')
            while packet.timestamp>=boundary:
                states.append(context.snapshot(boundary));boundary+=window_seconds
            context.add(packet)
    return states
