#!/usr/bin/env bash
# snap.sh — снапшоты sparse-копиями (raw не умеет внутренние).
# Использование: ./snap.sh create|apply|list <имя>
set -euo pipefail
VM_DIR="$(dirname "$0")"
IMG="$VM_DIR/beton-vm.raw"
SNAPDIR="$VM_DIR/snaps"
OP="${1:-}"; NAME="${2:-}"

running() { [[ -f "$VM_DIR/qemu.pid" ]] && kill -0 "$(cat "$VM_DIR/qemu.pid")" 2>/dev/null; }

case "$OP" in
  create)
    [[ -n "$NAME" ]] || { echo "нужно имя"; exit 2; }
    running && { echo "останови VM: ./halt.sh"; exit 2; }
    mkdir -p "$SNAPDIR"
    cp --sparse=always "$IMG" "$SNAPDIR/$NAME.raw"
    echo "снапшот $NAME ($(du -h "$SNAPDIR/$NAME.raw" | cut -f1))"
    ;;
  apply)
    [[ -n "$NAME" && -f "$SNAPDIR/$NAME.raw" ]] || { echo "нет снапшота $NAME"; exit 2; }
    running && { echo "останови VM: ./halt.sh"; exit 2; }
    cp --sparse=always "$SNAPDIR/$NAME.raw" "$IMG"
    echo "откат к $NAME"
    ;;
  list) ls "$SNAPDIR" 2>/dev/null || echo "снапшотов нет";;
  *) echo "usage: snap.sh create|apply|list <имя>"; exit 2;;
esac
