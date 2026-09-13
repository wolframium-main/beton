#!/usr/bin/env bash
# build.sh — ТОЛЬКО ДЛЯ VM. На хосте не запускать attach.
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null 2>&1 || { echo "VM: поставь $1"; exit 2; }; }

if [[ "${1:-}" == "--attach" ]]; then
  IFACE="${2:-}"
  [[ -z "$IFACE" ]] && { echo "usage: build.sh --attach <iface>"; exit 2; }
  [[ $EUID -ne 0 ]] && { echo "attach только под root в VM"; exit 2; }
  need tc; need bpftool
  [[ -f beton_sni_tc.o ]] || { echo "сначала собери без флагов"; exit 2; }
  tc qdisc add dev "$IFACE" clsact 2>/dev/null || true
  tc filter add dev "$IFACE" egress bpf da obj beton_sni_tc.o sec tc/egress
  echo "прицеплено к $IFACE (VM)"
  exit 0
fi

# Обычная сборка (тоже в VM: нужен clang+libbpf).
need clang
[[ -f patterns.h ]] || { echo "сначала: python3 codegen.py <домены> --out patterns.h"; exit 2; }
clang -O2 -target bpf -g -c beton_sni_tc.c -o beton_sni_tc.o \
  -I/usr/include -Wall -Wno-compare-distinct-pointer-types
echo "OK: beton_sni_tc.o"
echo "Проверить: bpftool prog show | grep beton (в VM)"
