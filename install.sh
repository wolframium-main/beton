#!/usr/bin/env bash
# install.sh — install beton to /usr/local/bin. Applies NO block.
# Applying is separate: sudo beton (interactive) after reading README.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m py_compile ./beton || { echo "build failed"; exit 1; }
rm -rf __pycache__
pkexec install -m 0755 ./beton /usr/local/bin/beton
echo "OK: beton installed. Next: sudo beton"
echo "Read README.md and VM_TESTS.md first. Do not run without a backup."
