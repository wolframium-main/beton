#!/usr/bin/env bash
# install.sh — положить beton в /usr/local/bin. Блок НЕ применяет.
# Применение — отдельно: sudo beton (интерактив) после чтения README.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m py_compile ./beton || { echo "сборка упала"; exit 1; }
rm -rf __pycache__
pkexec install -m 0755 ./beton /usr/local/bin/beton
echo "OK: beton установлен. Дальше: sudo beton"
echo "Сначала прочитай README.md и VM_TESTS.md. Без бэкапа не запускать."
