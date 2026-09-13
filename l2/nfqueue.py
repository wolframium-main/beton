"""L2 NFQUEUE-демон — второй носитель SNI-фильтра. ЗАПУСК ТОЛЬКО В VM ПОД ROOT.

Логика решения (verdict_for_payload) — чистый Python, тестируется без root.
Сеть (netfilterqueue) импортируется только в main(), в тестах не нужен.

Как давит: nft отправляет TCP->443 в очередь, демон вытаскивает TLS payload,
sni.extract_sni решает. Переименование бинаря/портативка не помогают:
смотрится соединение, а не процесс.

Честные зазоры — те же, что у TC-фильтра (см. l2/README.md): ECH, фрагментация.
Этот демон и есть заявленный фолбэк на случай войны с верифаером.
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
    """Вернуть (tls_payload, dport) для IPv4/TCP, иначе None. Строго по границам."""
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
    """DROP только для ClientHello с запрещенным SNI. Всё остальное — ACCEPT
    (невидимость: чужой трафик не трогаем вообще)."""
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
    ap = argparse.ArgumentParser(description="beton L2 NFQUEUE (только VM, только root)")
    ap.add_argument("--queue", type=int, default=7)
    ap.add_argument("--bases-file", required=True, help="файл с базовыми доменами")
    a = ap.parse_args()
    if os.geteuid() != 0:
        print("только root и только в VM")
        return 2
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        print("VM: поставь python-netfilterqueue; логика проверяется test_nfqueue.py без него")
        return 2
    bases = load_bases(a.bases_file)
    if not bases:
        print("пустой bases-file")
        return 2

    def cb(pkt):
        v = verdict_for_payload(pkt.get_payload(), bases)
        pkt.drop() if v == DROP else pkt.accept()

    print(f"L2 NFQUEUE: очередь {a.queue}, баз {len(bases)}. Ctrl+C — стоп (VM).")
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
