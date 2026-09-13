"""NFQUEUE verdict tests. No root, no netfilterqueue. Run: python3 test_nfqueue.py"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import nfqueue
from test_sni import build_hello  # reuse the hello constructor

BASES = {"youtube.com"}


def wrap_tcp(payload: bytes, dport: int = 443) -> bytes:
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6  # TCP
    total = 20 + 20 + len(payload)
    struct.pack_into("!H", ip, 2, total)
    tcp = bytearray(20)
    struct.pack_into("!H", tcp, 0, 12345)
    struct.pack_into("!H", tcp, 2, dport)
    tcp[12] = 0x50  # data offset 5
    return bytes(ip) + bytes(tcp) + payload


class TestVerdict(unittest.TestCase):
    def test_blocked_sni_drops(self):
        pkt = wrap_tcp(build_hello(["music.youtube.com"]))
        self.assertEqual(nfqueue.verdict_for_payload(pkt, BASES), nfqueue.DROP)

    def test_allowed_sni_accepts(self):
        pkt = wrap_tcp(build_hello(["example.com"]))
        self.assertEqual(nfqueue.verdict_for_payload(pkt, BASES), nfqueue.ACCEPT)

    def test_non_443_accepts(self):
        pkt = wrap_tcp(build_hello(["youtube.com"]), dport=8443)
        self.assertEqual(nfqueue.verdict_for_payload(pkt, BASES), nfqueue.ACCEPT)

    def test_non_tls_accepts(self):
        pkt = wrap_tcp(b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(nfqueue.verdict_for_payload(pkt, BASES), nfqueue.ACCEPT)

    def test_garbage_accepts(self):
        for bad in [b"", b"\x45\x00", b"\x60" + b"\x00" * 40]:
            self.assertEqual(nfqueue.verdict_for_payload(bad, BASES), nfqueue.ACCEPT)

    def test_lookalike_accepts(self):
        pkt = wrap_tcp(build_hello(["notyoutube.com"]))
        self.assertEqual(nfqueue.verdict_for_payload(pkt, BASES), nfqueue.ACCEPT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
