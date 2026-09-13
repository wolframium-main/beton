#!/usr/bin/env bash
# ssh.sh — выполнить команду в госте. Использование: ./ssh.sh [команда...]
set -euo pipefail
VM_DIR="$(dirname "$0")"
exec ssh -i "$VM_DIR/id_ed25519" -p 2222 -o StrictHostKeyChecking=no root@localhost "$@"
