"""L3 gate: предполётные проверки церемонии финализации. Только чтение, без root
ничего не меняет (проверки root/VM просто вернут FAIL).

Церемония запускается только в VM под root при наличии:
  /etc/beton/ALLOW_FINAL   — строка: Я ПРИНИМАЮ НЕОБРАТИМОСТЬ <дата>
  /etc/beton/VM_MATRIX_OK  — подпись прогона матрицы из VM_TESTS.md
  /var/lib/beton/           — установленный блок + бэкап pre-apply

Использование: python3 gate.py [--quiet]; код 0 = можно звать finalize.sh.
"""
from __future__ import annotations

import os
import subprocess
import sys

ALLOW_FINAL = "/etc/beton/ALLOW_FINAL"
MATRIX_OK = "/etc/beton/VM_MATRIX_OK"
DOMAINS = "/var/lib/beton/domains.txt"
ALLOW_PHRASE = "Я ПРИНИМАЮ НЕОБРАТИМОСТЬ"
VM_TYPES = {"qemu", "kvm", "vmware", "virtualbox", "microsoft", "parallels", "bhyve"}


def check_root() -> tuple[bool, str]:
    ok = os.geteuid() == 0
    return ok, "root ok" if ok else "нужен root (запуск только в VM)"


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
    return False, f"не VM (detect-virt={virt}): финализация только в виртуалке"


EFIVARS_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def read_efivar(name: str) -> int | None:
    try:
        with open(f"/sys/firmware/efi/efivars/{name}-{EFIVARS_GUID}", "rb") as f:
            return f.read()[-1]
    except OSError:
        return None


def check_uefi_setup() -> tuple[bool, str]:
    if not os.path.isdir("/sys/firmware/efi"):
        return False, "нет UEFI"
    setup = read_efivar("SetupMode")
    sb = read_efivar("SecureBoot")
    if setup is None:
        return False, "нет efivars (нужна прошивка с pflash VARS)"
    if setup == 1:
        return True, "Setup Mode on — можно enroll (SB включится после)"
    if sb == 1:
        return True, "SecureBoot on — ключи уже заведены"
    return False, "ни Setup Mode, ни SecureBoot: сбрось ключи в прошивке VM (Clear Keys)"


def check_allow() -> tuple[bool, str]:
    try:
        with open(ALLOW_FINAL, encoding="utf-8") as f:
            text = f.read()
        if ALLOW_PHRASE in text:
            return True, "ALLOW_FINAL ok"
        return False, "ALLOW_FINAL без фразы принятия"
    except OSError:
        return False, "нет /etc/beton/ALLOW_FINAL"


def check_matrix() -> tuple[bool, str]:
    ok = os.path.isfile(MATRIX_OK)
    return ok, "VM_MATRIX_OK ok" if ok else "нет /etc/beton/VM_MATRIX_OK (прогони VM_TESTS.md)"


def check_state() -> tuple[bool, str]:
    ok = os.path.isfile(DOMAINS)
    return ok, "блок установлен" if ok else "нет /var/lib/beton/domains.txt (сначала block)"


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
