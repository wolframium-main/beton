#!/usr/bin/env bash
# boot.sh — запуск VM в фоне (без root). Snapshot-режим НЕ используется:
# снапшоты делаются явно через snap.sh.
set -euo pipefail
VM_DIR="$(dirname "$0")"
IMG="$VM_DIR/beton-vm.raw"
OVMF_CODE="/usr/share/edk2-ovmf/x64/OVMF.4m.fd"
PIDF="$VM_DIR/qemu.pid"
LOG="$VM_DIR/serial.log"

[[ -f "$IMG" ]] || { echo "нет образа: сначала make-vm.sh через pkexec"; exit 2; }
if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  echo "VM уже запущена (pid $(cat "$PIDF"))"
  exit 0
fi
[[ -f "$VM_DIR/id_ed25519" ]] || { echo "нет ssh-ключа: make-vm.sh не добежал"; exit 2; }

qemu-system-x86_64 \
  -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive file="$IMG",format=raw,if=virtio \
  -bios "$OVMF_CODE" \
  -nic user,model=e1000,hostfwd=tcp::2222-:22 \
  -display none -serial file:"$LOG" \
  -daemonize -pidfile "$PIDF"
echo "VM стартует (pid $(cat "$PIDF")). Лог: $LOG"
"$VM_DIR/wait-ssh.sh"
