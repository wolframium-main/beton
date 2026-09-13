"""Тесты L2 SNI-ядра. Без root. Запуск: python3 test_sni.py (из каталога l2)."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import sni


def build_hello(names: list[str] | None) -> bytes:
    """Минимальный TLS ClientHello. names=None — без extension block."""
    rnd = b"\x11" * 32
    body = b"\x03\x03" + rnd + b"\x00"  # version + random + empty session
    body += struct.pack("!H", 2) + b"\x13\x01"  # 1 ciphersuite
    body += b"\x01\x00"  # compression
    if names is not None:
        entries = b""
        for n in names:
            nb = n.encode("ascii")
            entries += b"\x00" + struct.pack("!H", len(nb)) + nb
        snl = struct.pack("!H", len(entries)) + entries
        ext = struct.pack("!HH", 0x0000, len(snl)) + snl
        # добавляем шумовое расширение до и после, как в реальном hello
        noise = struct.pack("!HH", 0x000A, 2) + b"\x00\x00"
        ext = noise + ext + noise
        body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class TestExtract(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(sni.extract_sni(build_hello(["youtube.com"])), "youtube.com")

    def test_case_and_dot(self):
        self.assertEqual(sni.extract_sni(build_hello(["WWW.YouTube.COM."])), "www.youtube.com")

    def test_first_name_wins(self):
        self.assertEqual(
            sni.extract_sni(build_hello(["first.example", "second.example"])), "first.example")

    def test_no_extensions(self):
        self.assertIsNone(sni.extract_sni(build_hello(None)))

    def test_garbage(self):
        for bad in [b"", b"\x00" * 10, b"\x16\x03\x01\x00\x05junk!", build_hello(["a.com"])[:12]]:
            self.assertIsNone(sni.extract_sni(bad))

    def test_truncated_sni(self):
        full = build_hello(["youtube.com"])
        self.assertIsNone(sni.extract_sni(full[:-4]))

    def test_ech_honesty(self):
        # При ECH на проводе только внешнее имя: парсер честно вернет его,
        # а не скрытую цель. Скрытая цель SNI-фильтру недоступна в принципе.
        self.assertEqual(sni.extract_sni(build_hello(["cover.example"])), "cover.example")


class TestDecision(unittest.TestCase):
    BASES = {"youtube.com", "tiktok.com"}

    def test_exact(self):
        self.assertTrue(sni.is_blocked("youtube.com", self.BASES))

    def test_sub(self):
        self.assertTrue(sni.is_blocked("music.youtube.com", self.BASES))

    def test_suffix_lookalike(self):
        self.assertFalse(sni.is_blocked("notyoutube.com", self.BASES))
        self.assertFalse(sni.is_blocked("youtube.com.evil.com", self.BASES))

    def test_empty(self):
        self.assertFalse(sni.is_blocked(None, self.BASES))
        self.assertFalse(sni.is_blocked("", self.BASES))

    def test_bases_from_domains(self):
        self.assertEqual(sni.bases_from_domains(["www.youtube.com", "tiktok.com"]), self.BASES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
