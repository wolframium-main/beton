# L2 в VM: SNI-фильтр на соединении

Идея: давить коннект по SNI на egress, а не убивать процесс по имени.
Переименованный туннель и портативный браузер проигрывают одинаково:
имя не важно, важно куда идёт ClientHello.

## Состав
- `sni.py` — эталонная логика (парсер ClientHello + решение). Тестируется без root.
- `test_sni.py` — 12 тестов, включая ECH-честность.
- `nfqueue.py` — второй носитель: userspace-демон поверх NFQUEUE, то же ядро `sni.py`.
  Фолбэк на случай войны с eBPF-верифаером. Логика — 6 тестов без root,
  запуск демона — только VM под root (`--bases-file`, очередь 7).
- `test_nfqueue.py` — вердикты на собранных IPv4/TCP-пакетах.
- `codegen.py` — домены → `patterns.h` для eBPF (макс. 64 паттерна по 64 байта).
  Тот же формат умеет `../beton gen-ebpf` (паритет покрыт тестами).
- `beton_sni_tc.c` — TC egress prototype. Совпадение паттерна → SHOT.
- `build.sh` — сборка и цепление. ТОЛЬКО VM.

## Прогон в VM (со снапшотом)
```
python3 test_sni.py
python3 codegen.py youtube.com tiktok.com --out patterns.h
sudo ./build.sh
sudo ./build.sh --attach eth0
curl -m 8 -o /dev/null -w "%{http_code}\n" https://youtube.com   # ждём обрыв
curl -m 8 -o /dev/null -w "%{http_code}\n" https://example.com   # ждём 200
```

## Честные зазоры
- ECH: настоящее имя зашифровано, фильтр видит outer-SNI. ECH-цель ловят DNS/IP-слои.
- Фрагментация hello: проскок возможен, фиксируем замером; фолбэк — NFQUEUE-демон.
- QUIC/UDP-443 с ECH: SNI вообще не на проводе в открытом виде — держит IP-слой + punish.
