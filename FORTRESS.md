# FORTRESS — from an evening puzzle to a fortress (work plan, honestly)

The MVP lived entirely in the mutable filesystem → skilled with root removes it
in 10–30 minutes. The fortress moves the trust anchor out of the mutable
filesystem → root alone is no longer enough.

## Level 1 — close the cheap bypasses [DONE]
- [x] Infrastructure stoplist (DANGEROUS_BASES) — self-shot protection
- [x] Hardcoded-DNS :53 block to public resolvers (nft pubdns set)
- [x] Policies: +Brave/Vivaldi/Opera, Firefox+ESR
- [x] Killer of processes installed AFTER setup + allowlist
- [x] Ladder: restore → 3 removals/10min → 15min QUIC-drop with auto-lift
- [x] `enforce` also verifies browser policies (post-setup browsers covered)

## Level 2 — squeeze the connection, not the process name [DONE, MEASURED IN VM]
- [x] Reference `l2/sni.py` + 12 tests (ClientHello parser, verdict, ECH honesty)
- [x] Carrier 1: `l2/beton_sni_tc.c` (TC egress, SHOT on pattern) + codegen + build.sh
- [x] Carrier 2: `l2/nfqueue.py` (userspace fallback, same core) + 6 verdict tests
- [x] `beton gen-ebpf` (no root) + parity test against codegen
- [x] VM: both carriers measured, substring matcher replaced with real SNI parsing
- No TLS-MITM: breaks trust, exposes the guard, needs a CA in the store.

## Level 3 — anchor outside the mutable filesystem [DONE, CEREMONY RUN IN VM]
- [x] `l3/gate.py`: 6 checks (root/VM/UEFI+SB/ALLOW/MATRIX/block), 6 tests
- [x] `l3/finalize.sh`: bundle→fresh key→UKI→sbsign→sbverify→enroll→shred→FINAL
- [x] FINAL flag in `beton`: post-final `revert` answers code 4 (tested)
- [x] `l3/` early-restore systemd unit in initramfs (race with timer closed)
- [x] Separation of powers: `beton` has no self-destruct, only the offline ceremony
- [x] VM run: Setup Mode→enroll→reboot→SecureBoot on→signed UKI boot→revert=4

## What we do NOT promise even in the fortress
- Second device (phone/someone else's PC) — out of perimeter.
- Brand-new mirror with new domain+IP — only an allowlist lifestyle catches it,
  and that is a different product.
- Physical BIOS battery reset — the legal exit via reinstall.

## Order of work (completed)
L1 → VM matrix with hack-time measurement → L2 prototype in VM →
L3 after the green L2 matrix. Evidence: vm/RESULTS.md.
