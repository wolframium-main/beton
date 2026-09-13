"""lab-dns.py — pocket DNS for the lab. Answers only the test zones, REFUSED otherwise.
Listens on 0.0.0.0:53 (needs root: launch via pkexec). The guest UDP socket reaches 10.0.2.2.

Zones:
  megablock.test, *.megablock.test -> 192.0.2.10   (L1/L2 block target)
  fine.test, *.fine.test             -> 10.0.2.2      (live control, see below)
"""
import socket
import struct
import sys

ZONES = {
    b"megablock.test": "192.0.2.10",
    # fine.test — live control: resolves to the lab host itself (slirp: 10.0.2.2),
    # where lab-tls :18443 and lab-http :18080 listen.
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
