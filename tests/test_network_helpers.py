"""Check that the attack harness targets host data, never control TLS/ARP."""
import socket
import unittest
from network_helpers import protected_data


def frame(payload=17):
    packet = bytearray(54 + payload)
    packet[12:14] = b"\x08\x00"
    packet[14], packet[23] = 0x45, 6
    packet[16:18] = (40 + payload).to_bytes(2, "big")
    packet[26:30] = socket.inet_aton("10.0.1.1")
    packet[30:34] = socket.inet_aton("10.0.3.2")
    packet[36:38] = (8080).to_bytes(2, "big")
    packet[46] = 0x50
    return packet


class TargetSelection(unittest.TestCase):
    def test_selected_host_data_and_padding(self):
        packet = frame()
        self.assertEqual(protected_data(packet), len(packet))
        self.assertEqual(protected_data(packet + bytes(20)), len(packet))

    def test_control_and_empty_segments_untouched(self):
        self.assertIsNone(protected_data(frame(16)))
        packet = frame()
        packet[26:30] = socket.inet_aton("10.0.2.1")
        packet[30:34] = socket.inet_aton("10.0.2.2")
        packet[36:38] = (9443).to_bytes(2, "big")
        self.assertIsNone(protected_data(packet))

    def test_wrong_port_and_malformed_frames_untouched(self):
        packet = frame()
        packet[36:38] = (8081).to_bytes(2, "big")
        self.assertIsNone(protected_data(packet))
        self.assertIsNone(protected_data(frame()[:-1]))
        self.assertIsNone(protected_data(bytes(20)))
        packet = frame()
        packet[46] = 0xf0
        self.assertIsNone(protected_data(packet))


if __name__ == "__main__":
    unittest.main()
