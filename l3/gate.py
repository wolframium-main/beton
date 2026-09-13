"""L3 gate: preflight checks for the finalization ceremony. Read-only; without root
it changes nothing (root/VM checks simply return FAIL).

The ceremony runs only in a VM as root with:
  /etc/beton/ALLOW_FINAL   — line: I ACCEPT IRREVERSIBILITY <date>
  /etc/beton/VM_MATRIX_OK  — sign-off of the VM_TESTS.md matrix run
  /var/lib/beton/           — installed block + pre-apply backup

Usage: python3 gate.py [--quiet]; exit 0 = finalize.sh may run.
"""
from __future__ import annotations

import os
import subprocess
import sys

ALLOW_FINAL = "/etc/beton/ALLOW_FINAL"
MATRIX_OK = "/etc/beton/VM_MATRIX_OK"
DOMAINS = "/var/lib/beton/domains.txt"
ALLOW_PHRASE = "I ACCEPT IRREVERSIBILITY"
VM_TYPES = {"qemu", "kvm", "vmware", "virtualbox", "microsoft", "parallels", "bhyve"}


def check_root() -> tuple[bool, str]:
    ok = os.geteuid() == 0
    return ok, "root ok" if ok else "root required (VM only)"


def detect_virt() -> str:
    try:
        r = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "none"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def check_vm(virt: str | None = None) -> tuple[bool, str]:
    virt = detect_virt() if virt is None else virt
    if virt in VM_TYPES:
        return True, f"VM ok ({virt})"
    return False, f"not a VM (detect-virt={virt}): finalize in a VM only"


EFIVARS_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def read_efivar(name: str) -> int | None:
    try:
        with open(f"/sys/firmware/efi/efivars/{name}-{EFIVARS_GUID}", "rb") as f:
            return f.read()[-1]
    except OSError:
        return None


def check_uefi_setup() -> tuple[bool, str]:
    if not os.path.isdir("/sys/firmware/efi"):
        return False, "no UEFI"
    setup = read_efivar("SetupMode")
    sb = read_efivar("SecureBoot")
    if setup is None:
        return False, "no efivars (firmware with pflash VARS required)"
    if setup == 1:
        return True, "Setup Mode on — enroll possible (SB comes after)"
    if sb == 1:
        return True, "SecureBoot on — keys already enrolled"
    return False, "neither Setup Mode nor SecureBoot: reset keys in VM firmware (Clear Keys)"


def check_allow() -> tuple[bool, str]:
    try:
        with open(ALLOW_FINAL, encoding="utf-8") as f:
            text = f.read()
        if ALLOW_PHRASE in text:
            return True, "ALLOW_FINAL ok"
        return False, "ALLOW_FINAL lacks the acceptance phrase"
    except OSError:
        return False, "missing /etc/beton/ALLOW_FINAL"


def check_matrix() -> tuple[bool, str]:
    ok = os.path.isfile(MATRIX_OK)
    return ok, "VM_MATRIX_OK ok" if ok else "missing /etc/beton/VM_MATRIX_OK (run VM_TESTS.md)"


def check_state() -> tuple[bool, str]:
    ok = os.path.isfile(DOMAINS)
    return ok, "block installed" if ok else "missing /var/lib/beton/domains.txt (block first)"


def run_all() -> list[tuple[str, bool, str]]:
    return [
        ("root", *check_root()),
        ("vm", *check_vm()),
        ("uefi-setup", *check_uefi_setup()),
        ("allow", *check_allow()),
        ("matrix", *check_matrix()),
        ("state", *check_state()),
    ]


def main() -> int:
    quiet = "--quiet" in sys.argv[1:]
    results = run_all()
    ok_all = all(ok for _, ok, _ in results)
    if not quiet:
        for name, ok, msg in results:
            print(f"[{'OK' if ok else 'FAIL'}] {name}: {msg}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
