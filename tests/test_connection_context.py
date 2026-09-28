import unittest
from types import SimpleNamespace
from pipeline.connection_context import ConnectionContext


def packet(time,dst='b',sport=100,ack=0,proto=6):
    return SimpleNamespace(timestamp=time,src='a',dst=dst,src_port=sport,dst_port=80,protocol=proto,syn=1,ack=ack)

class ConnectionContextTests(unittest.TestCase):
    def test_retries_and_fanout_are_distinguishable(self):
        retry=ConnectionContext();scan=ConnectionContext()
        for i in range(3):retry.add(packet(i));scan.add(packet(i,dst=str(i)))
        r=retry.snapshot(5);s=scan.snapshot(5)
        self.assertEqual(r['context_syn_destinations'],1)
        self.assertEqual(s['context_syn_destinations'],3)
        self.assertAlmostEqual(r['context_repeated_syn_fraction'],2/3)
        self.assertEqual(s['context_repeated_syn_fraction'],0)

    def test_future_packets_cannot_change_past_snapshots(self):
        c=ConnectionContext();c.add(packet(1));before=c.snapshot(5)
        c.add(packet(6,dst='new'))
        self.assertEqual(before['context_destination_endpoints'],1)
        with self.assertRaisesRegex(ValueError,'chronological'):c.snapshot(5)
        with self.assertRaisesRegex(ValueError,'chronological'):c.add(packet(4))

    def test_eviction_and_capture_isolation(self):
        c=ConnectionContext(seconds=10);c.add(packet(0));c.add(packet(1,dst='c'))
        self.assertEqual(c.snapshot(10)['context_packets'],1)
        self.assertEqual(c.snapshot(11)['context_packets'],0)
        self.assertEqual(c.snapshot(11)['context_syn_destinations'],0)
        self.assertEqual(ConnectionContext().snapshot(11)['context_observed_seconds'],0)

    def test_limits_fail_closed_and_syn_ack_is_not_new_attempt(self):
        c=ConnectionContext(max_packets=1);c.add(packet(0,ack=1))
        self.assertEqual(c.snapshot(0)['context_syn_packets'],0)
        with self.assertRaisesRegex(ValueError,'limit exceeded'):c.add(packet(1))
        with self.assertRaisesRegex(ValueError,'invalid'):c.snapshot(1)
        with self.assertRaises(ValueError):ConnectionContext(seconds=float('nan'))

    def test_pcap_boundary_excludes_future_packet_and_final_partial_window(self):
        import tempfile
        from pathlib import Path
        from scapy.all import Ether,IP,TCP,wrpcap
        from pipeline.connection_context import context_states
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'context.pcap';packets=[]
            for t,dst in [(100,'10.0.0.2'),(101,'10.0.0.2'),(105,'10.0.0.3'),(110,'10.0.0.4')]:
                p=Ether()/IP(src='10.0.0.1',dst=dst)/TCP(sport=1000,dport=80,flags='S');p.time=t;packets.append(p)
            wrpcap(str(path),packets);states=context_states(path)
            self.assertEqual(len(states),2)
            self.assertEqual(states[0]['context_destination_endpoints'],1)
            self.assertEqual(states[1]['context_destination_endpoints'],2)
            self.assertEqual(states[0]['context_packets'],2)
