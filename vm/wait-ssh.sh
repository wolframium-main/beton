#!/usr/bin/env bash
# wait-ssh.sh — wait for the guest sshd (up to 120s).
set -uo pipefail
VM_DIR="$(dirname "$0")"
for i in $(seq 1 60); do
  if ssh -i "$VM_DIR/id_ed25519" -p 2222 -o StrictHostKeyChecking=no \
       -o ConnectTimeout=2 -o BatchMode=yes root@localhost true 2>/dev/null; then
    echo "SSH ready (${i}x2s)"
    exit 0
  fi
  sleep 2
done
echo "SSH never came up. See $VM_DIR/serial.log"
exit 1
