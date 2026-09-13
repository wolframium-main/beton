# Changelog

## 0.1.0 (2026-09-13) — первый проверенный релиз
- L1: hosts + nft (IP/DoT/DoH/hardcoded-DNS) + политики браузеров
  (Chromium/Firefox/ESR/Brave/Vivaldi/Opera) + сторож 30с + pacman-хук +
  киллер пост-установочных обходов + allowlist + лестница punish + стоп-лист инфры
- L2: eBPF TC SNI-фильтр с парсингом ClientHello и границами домена
  (bare-hostname brane: substring давал ложняк на notfoo — исправлено),
  порт параметризован; NFQUEUE-демон — второй носитель (юнит-тесты, вживую не цеплен)
- L3: церемония необратимости — гейт из 6 проверок, свежий ключ sbctl, UKI,
  sbsign+sbverify, enroll, shred всего хранилища, FINAL-флаг (revert отвечает 4),
  systemd-юнит раннего восстановления в initramfs, boot-запись
- Замерено в VM (см. vm/RESULTS.md): матрица L1, SNI-замеры L2
  (цель/поддомен 000, чужой 200 за 4мс, двойник пощажён), живой Chromium
  (bare-hostname блокирует, *://-формы Chrome 153 игнорирует — оставлены для FF),
  полный цикл L1+L2+L3 с нуля + перезагрузка в signed UKI под Secure Boot
- Полевые фиксы: зависший enable --now таймера, unlock в начале apply,
  pipefail+head, ESP-парсинг через sysfs, efi-копия после enroll,
  shebang sh в initramfs, run_latehook не работает под systemd (юнит вместо),
  wants-симлинк явно, микродод опционален

## Честные зазоры 0.1.0
- ECH-цели видит только outer-SNI (ловят DNS/IP-слои)
- Второй девайс/новое зеркало/физический сброс BIOS — вне периметра
- NFQUEUE-носитель не поднимался вживую (только логика + тесты)
- Firefox WebsiteFilter проверен на уровне файлов, не живым запуском
