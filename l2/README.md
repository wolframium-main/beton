# L2 in a VM: SNI filter on the connection

Idea: kill the egress connection by SNI instead of killing processes by name.
A renamed tunnel or a portable browser lose the same way: the name does not
matter, the ClientHello destination does.

## Contents
- `sni.py` — reference logic (ClientHello parser + verdict). Tested without root.
- `test_sni.py` — 12 tests, including ECH honesty.
- `nfqueue.py` — second carrier: userspace daemon over NFQUEUE, same `sni.py` core.
  Fallback in case of war with the eBPF verifier. Logic — 6 tests without root,
  daemon launch — VM + root only (`--bases-file`, queue 7).
- `test_nfqueue.py` — verdicts on crafted IPv4/TCP packets.
- `codegen.py` — domains → `patterns.h` for eBPF (max 64 patterns x 64 bytes,
  `--port`, default 443). `../beton gen-ebpf` produces the same format (parity tested).
- `beton_sni_tc.c` — TC egress prototype: parses SNI, compares on domain
  boundaries (exact or subdomain; `notfoo.com` does NOT match — substring
  matching was replaced after a measured false positive). Match → SHOT.
- `build.sh` — build and attach. VM ONLY.

## Run in VM (with snapshot)
```
python3 test_sni.py
python3 codegen.py youtube.com tiktok.com --out patterns.h
sudo ./build.sh
sudo ./build.sh --attach eth0
curl -m 8 -o /dev/null -w "%{http_code}\n" https://youtube.com   # expect drop
curl -m 8 -o /dev/null -w "%{http_code}\n" https://example.com   # expect 200
```

## Honest gaps
- ECH: the real name is encrypted, the filter sees the outer SNI. ECH targets
  are caught by the DNS/IP layers.
- Fragmented hello: may slip through, measured; fallback is the NFQUEUE daemon.
- QUIC/UDP-443 with ECH: no cleartext SNI on the wire at all — IP layer + punish hold it.
