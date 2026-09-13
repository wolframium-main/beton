#!/usr/bin/env bash
# boot.sh — start the VM in background (no root). No auto-snapshots:
# snapshots are explicit via snap.sh.
set -euo pipefail
VM_DIR="$(dirname "$0")"
IMG="$VM_DIR/beton-vm.raw"
OVMF_CODE="/usr/share/edk2-ovmf/x64/OVMF.4m.fd"
PIDF="$VM_DIR/qemu.pid"
LOG="$VM_DIR/serial.log"

[[ -f "$IMG" ]] || { echo "no image: run make-vm.sh via pkexec first"; exit 2; }
if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  echo "VM already running (pid $(cat "$PIDF"))"
  exit 0
fi
[[ -f "$VM_DIR/id_ed25519" ]] || { echo "no ssh key: make-vm.sh did not finish"; exit 2; }

qemu-system-x86_64 \
  -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive file="$IMG",format=raw,if=virtio \
  -bios "$OVMF_CODE" \
  -nic user,model=e1000,hostfwd=tcp::2222-:22 \
  -display none -serial file:"$LOG" \
  -daemonize -pidfile "$PIDF"
echo "VM starting (pid $(cat "$PIDF")). Log: $LOG"
"$VM_DIR/wait-ssh.sh"
