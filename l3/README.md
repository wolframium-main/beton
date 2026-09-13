# L3: irreversibility ceremony (VM only)

Concept: the trust anchor moves out of the mutable filesystem. Root does not
get stronger after the ceremony — it can edit, but cannot boot the edits
without a signature.

## Contents
- `gate.py` — 6 preflight checks (root, VM, UEFI+SecureBoot, ALLOW_FINAL,
  VM_MATRIX_OK, installed block). Read-only. Red on the host — by design.
- `test_gate.py` — 6 gate tests.
- `finalize.sh` — the ceremony itself (VM, root, `--i-am-sure`): policy bundle →
  fresh key → UKI → sbsign → sbverify → enroll → `shred -u` of the keys → FINAL.
- Early restore: `mkinitcpio-hook-beton` + `mkinitcpio-install-beton` +
  `beton-restore.sh` + `beton-restore.service` — a systemd unit inside initramfs
  restoring hosts before switch-root (run_latehook never fires under a systemd
  initramfs — proven by missing kmsg; the wants-symlink must be explicit).
- Separation of powers as a safety feature: `beton` has NO self-destruct command —
  only the offline `l3/` ceremony with a gate. Cannot be triggered by accident.

## Why this holds against a hacker
1. Nothing to re-sign with: the key lived minutes and went under shred.
2. Booting an unsigned kernel/image: Secure Boot refuses.
3. LiveUSB: needs a firmware reset (password not held by the user) + reinstall.
4. `revert-for-testing` after FINAL answers code 4 — the function is dead.
5. Early boot stage already restores the block — the race with the timer is closed.

## What we do NOT promise (see FORTRESS.md)
Second device, brand-new mirror with new domain+IP, physical BIOS battery reset.
The ceremony never touches `/home`.
