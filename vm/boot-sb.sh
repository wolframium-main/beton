#!/usr/bin/env bash
# boot-sb.sh — boot the VM with SecureBoot firmware (for L3). No root.
# VARS are private (template copy), live in vm/, never committed.
set -euo pipefail
VM_DIR="$(dirname "$0")"
IMG="$VM_DIR/beton-vm.raw"
CODE="/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.4m.fd"
VARS_TPL="/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd"
VARS="$VM_DIR/OVMF_VARS.beton.fd"
PIDF="$VM_DIR/qemu.pid"
LOG="$VM_DIR/serial.log"

[[ -f "$IMG" ]] || { echo "no image"; exit 2; }
if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  echo "VM already running"; exit 0
fi
[[ -f "$VARS" ]] || { cp "$VARS_TPL" "$VARS"; echo "VARS created: $VARS"; }

TPMDIR="$VM_DIR/tpm"
mkdir -p "$TPMDIR"
if ! pgrep -f "swtpm socket.*$TPMDIR" >/dev/null 2>&1; then
  swtpm socket --tpmstate dir="$TPMDIR" --ctrl type=unixio,path="$TPMDIR/swtpm.sock" \
    --tpm2 --daemon --pid file="$TPMDIR/swtpm.pid"
  echo "swtpm started"
fi

qemu-system-x86_64 \
  -enable-kvm -cpu host -machine q35,smm=on -m 2048 -smp 2 \
  -chardev socket,id=chrtpm,path="$TPMDIR/swtpm.sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -drive file="$IMG",format=raw,if=virtio \
  -drive file="$CODE",format=raw,if=pflash,readonly=on \
  -drive file="$VARS",format=raw,if=pflash \
  -nic user,model=e1000,hostfwd=tcp::2222-:22 \
  -display none -serial file:"$LOG" \
  -daemonize -pidfile "$PIDF"
echo "VM(SB) starting. Log: $LOG"
"$VM_DIR/wait-ssh.sh"
