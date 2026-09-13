"""L2: SNI-ядро. Чистый Python, без root. Та же логика ляжет в eBPF TC-фильтр.

extract_sni: разбирает TLS ClientHello, возвращает server_name или None.
is_blocked: решение рвать/пустить по списку базовых доменов.

Честное ограничение: при ECH (Encrypted Client Hello) настоящее имя зашифровано,
на проводе видно только внешнее (outer) SNI. Парсер возвращает то, что на проводе;
невидимость ECH-цели для SNI-фильтра — фундаментальна, ее закрывают DNS/IP-слои.
"""
from __future__ import annotations


def extract_sni(data: bytes) -> str | None:
    try:
        return _parse(data)
    except (IndexError, ValueError):
        return None


def _u16(b: bytes, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def _parse(data: bytes) -> str | None:
    if len(data) < 5 or data[0] != 0x16:  # TLS record: Handshake
        return None
    rec_len = _u16(data, 3)
    if len(data) < 5 + rec_len:
        return None
    hs = data[5:5 + rec_len]
    if len(hs) < 4 or hs[0] != 0x01:  # ClientHello
        return None
    body_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    body = hs[4:4 + body_len]
    if len(body) < body_len:
        return None
    o = 2 + 32  # version + random
    if len(body) < o + 1:
        return None
    sid_len = body[o]
    o += 1 + sid_len
    if len(body) < o + 2:
        return None
    cs_len = _u16(body, o)
    o += 2 + cs_len
    if len(body) < o + 1:
        return None
    cm_len = body[o]
    o += 1 + cm_len
    if len(body) < o + 2:
        return None
    ext_total = _u16(body, o)
    o += 2
    ext_end = o + ext_total
    if len(body) < ext_end:
        return None
    while o + 4 <= ext_end:
        etype = _u16(body, o)
        elen = _u16(body, o + 2)
        o += 4
        if o + elen > ext_end:
            return None
        if etype == 0x0000:  # server_name
            ed = body[o:o + elen]
            if len(ed) < 2:
                return None
            list_len = _u16(ed, 0)
            p = 2
            end = 2 + list_len
            if len(ed) < end:
                return None
            while p + 3 <= end:
                ntype = ed[p]
                nlen = _u16(ed, p + 1)
                p += 3
                if p + nlen > end:
                    return None
                if ntype == 0:  # host_name, берем первое
                    try:
                        return ed[p:p + nlen].decode("ascii").lower().strip().rstrip(".")
                    except UnicodeDecodeError:
                        return None
                p += nlen
            return None
        o += elen
    return None


def base_of_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    return d[4:] if d.startswith("www.") else d


def is_blocked(host: str | None, blocked_bases: set[str] | list[str]) -> bool:
    """Рвать соединение, если host совпал с базой или ее поддоменом."""
    if not host:
        return False
    h = host.strip().lower().rstrip(".")
    if not h:
        return False
    for b in blocked_bases:
        if h == b or h.endswith("." + b):
            return True
    return False


def bases_from_domains(domains: list[str]) -> set[str]:
    return {base_of_domain(d) for d in domains if d.strip()}
