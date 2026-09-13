#!/usr/bin/env bash
# halt.sh — остановить VM.
set -uo pipefail
VM_DIR="$(dirname "$0")"
if [[ -f "$VM_DIR/qemu.pid" ]] && kill -0 "$(cat "$VM_DIR/qemu.pid")" 2>/dev/null; then
  "$VM_DIR/ssh.sh" poweroff 2>/dev/null || kill "$(cat "$VM_DIR/qemu.pid")" 2>/dev/null || true
  for i in $(seq 1 30); do
    kill -0 "$(cat "$VM_DIR/qemu.pid" 2>/dev/null)" 2>/dev/null || break
    sleep 1
  done
  rm -f "$VM_DIR/qemu.pid"
  echo "VM остановлена"
else
  echo "VM не запущена"
fi
