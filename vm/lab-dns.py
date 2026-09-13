"""lab-dns.py — карманный DNS для стенда. Отвечает только тестовые зоны, остальное REFUSED.
Слушает 0.0.0.0:53 (нужен root: запуск через pkexec). UDP-сокет гостя до 10.0.2.2 доходит.

Зоны:
  megablock.test, *.megablock.test -> 192.0.2.10   (цель блока L1/L2)
  fine.test, *.fine.test             -> 192.0.2.20   (контроль, всегда жив)
"""
import socket
import struct
import sys

ZONES = {
    b"megablock.test": "192.0.2.10",
    # fine.test — живой контроль: резолвится в сам хост стенда (slirp: 10.0.2.2),
    # где слушают lab-tls :18443 и lab-http :18080.
    b"fine.test": "10.0.2.2",
}


def decode_name(pkt: bytes, off: int) -> tuple[bytes, int]:
    labels = []
    while True:
        ln = pkt[off]
        off += 1
        if ln == 0:
            break
        labels.append(pkt[off:off + ln].lower())
        off += ln
    return b".".join(labels), off


def match(name: bytes) -> str | None:
    for zone, ip in ZONES.items():
        if name == zone or name.endswith(b"." + zone):
            return ip
    return None


def handle(pkt: bytes) -> bytes:
    try:
        tid, flags, qd, _, _, _ = struct.unpack("!HHHHHH", pkt[:12])
        name, off = decode_name(pkt, 12)
        qtype, qclass = struct.unpack("!HH", pkt[off:off + 4])
    except Exception:
        return b""
    ip = match(name)
    if ip is None or qtype != 1:
        return struct.pack("!HHHHHH", tid, 0x8183, qd, 0, 0, 0) + pkt[12:]
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return struct.pack("!HHHHHH", tid, 0x8180, qd, 1, 0, 0) + pkt[12:off + 4] + ans


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    a = ap.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((a.bind, 53))
    print(f"lab-dns on {a.bind}:53", flush=True)
    while True:
        data, addr = s.recvfrom(512)
        out = handle(data)
        if out:
            s.sendto(out, addr)


if __name__ == "__main__":
    raise SystemExit(main())
