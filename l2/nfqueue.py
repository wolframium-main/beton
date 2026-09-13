"""L2 NFQUEUE daemon — the second SNI-filter carrier. RUN ONLY IN A VM AS ROOT.

Verdict logic (verdict_for_payload) is pure Python, tested without root.
Networking (netfilterqueue) is imported only in main(), tests do not need it.

How it squeezes: nft sends TCP->443 to the queue, the daemon extracts the TLS payload,
sni.extract_sni decides. Renamed binaries/portables do not help:
the connection is watched, not the process.

Honest gaps — same as the TC filter (see l2/README.md): ECH, fragmentation.
This daemon is the declared fallback in case of war with the verifier.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sni import extract_sni, is_blocked

DROP = "drop"
ACCEPT = "accept"


def tls_payload_of_ipv4(packet: bytes) -> tuple[bytes, int] | None:
    """Return (tls_payload, dport) for IPv4/TCP, else None. Strictly within bounds."""
    if len(packet) < 20 or (packet[0] >> 4) != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 20:
        return None
    if packet[9] != 6:  # TCP
        return None
    tcp_off = ihl
    dport = struct.unpack("!H", packet[tcp_off + 2:tcp_off + 4])[0]
    doff = ((packet[tcp_off + 12] >> 4) & 0x0F) * 4
    if doff < 20:
        return None
    start = tcp_off + doff
    if start > len(packet):
        return None
    return packet[start:], dport


def verdict_for_payload(packet: bytes, blocked_bases: set[str] | list[str]) -> str:
    """DROP only for ClientHello with a banned SNI. Everything else — ACCEPT
    (invisibility: foreign traffic untouched at all)."""
    parsed = tls_payload_of_ipv4(packet)
    if parsed is None:
        return ACCEPT
    tls, dport = parsed
    if dport != 443 or len(tls) < 6:
        return ACCEPT
    host = extract_sni(tls)
    return DROP if is_blocked(host, blocked_bases) else ACCEPT


def load_bases(path: str) -> set[str]:
    out: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            d = line.strip().lower().rstrip(".")
            if d and not d.startswith("#"):
                out.add(d[4:] if d.startswith("www.") else d)
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="beton L2 NFQUEUE (VM only, root only)")
    ap.add_argument("--queue", type=int, default=7)
    ap.add_argument("--bases-file", required=True, help="file with base domains")
    a = ap.parse_args()
    if os.geteuid() != 0:
        print("root only and VM only")
        return 2
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        print("VM: install python-netfilterqueue; logic is covered by test_nfqueue.py without it")
        return 2
    bases = load_bases(a.bases_file)
    if not bases:
        print("empty bases-file")
        return 2

    def cb(pkt):
        v = verdict_for_payload(pkt.get_payload(), bases)
        pkt.drop() if v == DROP else pkt.accept()

    print(f"L2 NFQUEUE: queue {a.queue}, {len(bases)} bases. Ctrl+C stops (VM).")
    print("nft glue (VM, root): tcp dport 443 queue num 7")
    q = NetfilterQueue()
    q.bind(a.queue, cb)
    try:
        q.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
