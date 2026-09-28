from pathlib import Path
import tempfile
import unittest
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap
from pipeline.pcap_replay import StreamingPcapReplay


class ObservedNetworkTests(unittest.TestCase):
    def test_connections_only_include_processed_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            packets = []
            for timestamp, dst, port in [(100, '10.0.0.2', 443), (102, '10.0.0.2', 443), (180, '10.0.0.3', 22)]:
                packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='10.0.0.1', dst=dst) / TCP(dport=port, flags='S')
                packet.time = timestamp
                packets.append(packet)
            wrpcap(str(path), packets)
            replay = StreamingPcapReplay(path)
            self.addCleanup(replay.close)
            self.assertEqual(replay.status()['observed_network']['packets_in_scope'], 0)
            first = replay.advance(5)['observed_network']
            self.assertEqual(first['packets_in_scope'], 2)
            self.assertEqual(first['host_count'], 2)
            self.assertEqual(first['syn_requests'], 2)
            self.assertEqual(first['connections'], [{'src':'10.0.0.1','dst':'10.0.0.2','destination_port':443,'protocol':6,'packets':2}])
            replay.advance(60)
            final = replay.advance(30)['observed_network']
            self.assertEqual(final['host_count'], 3)
            self.assertEqual(final['destination_port_count'], 2)
            self.assertEqual(final['packets_in_scope'], 3)
            self.assertEqual(replay.advance(5)['observed_network'], final)

    def test_protocol_bytes_and_ports_exclude_non_transport_pseudo_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'mixed.pcap'
            packets = []
            for index, transport in enumerate([ICMP(), UDP(dport=53), TCP(dport=443, flags='S'), TCP(dport=443, flags='SA')]):
                packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='10.0.0.1', dst='10.0.0.2') / transport
                packet.time = 100 + index
                packets.append(packet)
            future = packets[0].copy(); future.time = 170
            wrpcap(str(path), packets + [future])
            replay = StreamingPcapReplay(path)
            self.addCleanup(replay.close)
            network = replay.advance(5)['observed_network']
            self.assertEqual(network['captured_packet_bytes'], sum(len(p) for p in packets))
            self.assertEqual(network['destination_port_count'], 2)
            self.assertEqual(network['syn_requests'], 1)
            self.assertEqual({p['name']: p['packets'] for p in network['protocols']}, {'TCP': 2, 'ICMP': 1, 'UDP': 1})
            self.assertEqual(sum(p['captured_packet_bytes'] for p in network['protocols']), network['captured_packet_bytes'])

    def test_protocol_summary_uses_bounded_recent_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'empty-scope.pcap'
            packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')/IP()/TCP()
            packet.time = 100
            wrpcap(str(path), [packet])
            replay = StreamingPcapReplay(path)
            self.addCleanup(replay.close)
            for _ in range(10000):
                replay._observed_packets.append(('10.0.0.1','10.0.0.2',53,17,0,0,42))
            replay._observed_packets.append(('10.0.0.1','10.0.0.2',443,6,1,0,54))
            network = replay.observed_network()
            self.assertEqual(network['packets_in_scope'], 10000)
            self.assertEqual(network['captured_packet_bytes'], 9999*42+54)
            self.assertEqual(network['protocols'][0]['packets'], 9999)
