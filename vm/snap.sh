#!/usr/bin/env bash
# snap.sh — snapshots as sparse copies (raw has no internal ones).
# Usage: ./snap.sh create|apply|list <name>
set -euo pipefail
VM_DIR="$(dirname "$0")"
IMG="$VM_DIR/beton-vm.raw"
SNAPDIR="$VM_DIR/snaps"
OP="${1:-}"; NAME="${2:-}"

running() { [[ -f "$VM_DIR/qemu.pid" ]] && kill -0 "$(cat "$VM_DIR/qemu.pid")" 2>/dev/null; }

case "$OP" in
  create)
    [[ -n "$NAME" ]] || { echo "name required"; exit 2; }
    running && { echo "stop the VM first: ./halt.sh"; exit 2; }
    mkdir -p "$SNAPDIR"
    cp --sparse=always "$IMG" "$SNAPDIR/$NAME.raw"
    echo "snapshot $NAME ($(du -h "$SNAPDIR/$NAME.raw" | cut -f1))"
    ;;
  apply)
    [[ -n "$NAME" && -f "$SNAPDIR/$NAME.raw" ]] || { echo "no snapshot $NAME"; exit 2; }
    running && { echo "stop the VM first: ./halt.sh"; exit 2; }
    cp --sparse=always "$SNAPDIR/$NAME.raw" "$IMG"
    echo "rolled back to $NAME"
    ;;
  list) ls "$SNAPDIR" 2>/dev/null || echo "no snapshots";;
  *) echo "usage: snap.sh create|apply|list <name>"; exit 2;;
esac
