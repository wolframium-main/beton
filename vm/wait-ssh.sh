#!/usr/bin/env bash
# wait-ssh.sh — ждать sshd гостя (до 120с).
set -uo pipefail
VM_DIR="$(dirname "$0")"
for i in $(seq 1 60); do
  if ssh -i "$VM_DIR/id_ed25519" -p 2222 -o StrictHostKeyChecking=no \
       -o ConnectTimeout=2 -o BatchMode=yes root@localhost true 2>/dev/null; then
    echo "SSH готов (${i}x2с)"
    exit 0
  fi
  sleep 2
done
echo "SSH не дождались. Смотри $VM_DIR/serial.log"
exit 1
