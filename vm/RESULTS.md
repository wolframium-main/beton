# Замеры стенда (VM qemu/kvm, герметичный lab-DNS/TLS, 2026-09-13)

## L1 (userspace)
- apply: hosts OK, nft OK (сет 192.0.2.10 из lab-DNS), timer active, backup создан
- снос hosts+nft руками → автовосстановление таймером (~30–50с в VM), tamper=1 в логе
- ручной enforce → восстановление + tamper++
- киллер: /tmp/tor (comm=tor, exe новее установки) убит, запись в лог
- allowlist: tor в списке → пережил enforce
- 3 сноса/10мин → punish АКТИВЕН (таблица beton_punish, QUIC-drop), автоснятие по сроку
- pacman -U → хук отработал (enforce, молча т.к. compliant)
- curl: megablock.test → getent 0.0.0.0 + 000; fine.test → 200 (и под punish тоже 200)
- revert → чисто (hosts без меток, таблиц нет, таймера нет)
- НАХОДКА: `enable --now` после reinstall оставляет таймер в elapsed без тиков.
  Исправлено в beton: enable + restart с проверкой (код + повторный замер OK).

## L2 (eBPF TC egress, паттерн megablock.test, порт стенда 18443)
- v1 substring: цель 000, но и notmegablock.test 000 (ложняк) → переписано на парсинг SNI
- v2 SNI-парсер: megablock.test 000, music.megablock.test 000,
  fine.test 200 за ~4мс, notmegablock.test 200
- по пути пойманы и исправлены: отсутствие linux/in.h, окно 512Б мало под реальные
  hello (стало 1024 + clamp min(ext_end,end)), порт параметризован (BETON_PORT)
- верифаер пропустил обе версии; v2 прицеплен и замерен

## L3 — финализация в VM (SecureBoot + custom keys + signed UKI)
- гейт: 6 проверок; на хосте красный, в VM зелёный (Setup Mode → enroll → SB on)
- церемония: бандл SHA256 → sbctl create-keys → ukify → sbsign → sbverify →
  enroll-keys --custom --tpm-eventlog (swtpm в VM) → shred всего /var/lib/sbctl →
  FINAL → boot-запись. EXIT:0
- после: ключей нет нигде (find), revert отвечает кодом 4, boot-запись первая
- перезагрузка: SecureBoot Enabled, BootCurrent=signed UKI, cmdline beton.final=1,
  блок (hosts/nft/timer) пережил
- раннее восстановление: systemd-юнит beton-restore.service в initramfs
  (run_latehook под systemd НЕ вызывается — доказано отсутствием kmsg;
  wants-симлинк делать явно — add_systemd_unit его не ставит)
- замер окна: снос hosts+nft + мгновенный ребут → на t+25с (nft ещё PENDING,
  таймер не тикал) hosts уже восстановлен юнитом, getent 0.0.0.0
- полевые находки и фиксы: pipefail+head (SIGPIPE 141), ESP-парсинг через
  lsblk PKNAME + /sys (не sed), efi-копия в ESP только после успеха enroll,
  unlock в начале apply, enable+restart таймера, микродод необязателен,
  shebang sh в initramfs, rm юнита из живой системы после упаковки
