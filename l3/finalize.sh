#!/usr/bin/env bash
# finalize.sh — ЦЕРЕМОНИЯ НЕОБРАТИМОСТИ. ТОЛЬКО VM. На хосте откажет гейт.
#
# Что делает: собирает политику в образ, строит UKI, подписывает СВЕЖИМ ключом,
# проверяет подпись, кладёт ключ под shred, ставит FINAL-флаг (убивает revert).
# После неё снять блок = сброс прошивки + переустановка. /home не трогает.
#
# Порядок в VM (со снапшотом!):
#   1. pacman -S systemd-ukify sbctl sbsigntools cryptsetup (REVIEW: пакеты Arch)
#   2. Прошить VM в Setup Mode, включить SecureBoot (настройки гипервизора)
#   3. sudo ./beton block ... && прогнать VM_TESTS.md, записать /etc/beton/VM_MATRIX_OK
#   4. echo "Я ПРИНИМАЮ НЕОБРАТИМОСТЬ $(date -I)" | sudo tee /etc/beton/ALLOW_FINAL
#   5. sudo bash l3/finalize.sh --i-am-sure
set -euo pipefail
cd "$(dirname "$0")/.."

[[ "${1:-}" == "--i-am-sure" ]] || { echo "без --i-am-sure не работаю"; exit 2; }
[[ $EUID -eq 0 ]] || { echo "только root в VM"; exit 2; }

echo "== гейт =="
python3 l3/gate.py || { echo "гейт красный — стоп"; exit 1; }

WORK=/root/beton-final
mkdir -p "$WORK"
DOMAINS=$(cat /var/lib/beton/domains.txt | tr '\n' ' ')
echo "== политика: $DOMAINS"

echo "== бандл политики =="
mkdir -p "$WORK/policy"
cp /var/lib/beton/domains.txt "$WORK/policy/"
cp /etc/beton/rules.nft "$WORK/policy/"
python3 ./beton gen-ebpf $DOMAINS --out "$WORK/policy/patterns.h"
sha256sum "$WORK/policy/"* | tee "$WORK/policy/SHA256SUMS"

echo "== ранний hosts-блок в initramfs (до UKI!) =="
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p /etc/initcpio/hooks /etc/initcpio/install
cp "$SCRIPT_DIR/mkinitcpio-hook-beton" /etc/initcpio/hooks/beton
cp "$SCRIPT_DIR/mkinitcpio-install-beton" /etc/initcpio/install/beton
cp "$SCRIPT_DIR/beton-restore.sh" /usr/bin/beton-restore
cp "$SCRIPT_DIR/beton-restore.service" /etc/systemd/system/beton-restore.service
chmod 755 /usr/bin/beton-restore
# hosts.block: слепок текущей секции (initramfs доливает её до switch_root)
awk '/>>> BETON >>>/,/<<< BETON <<</' /etc/hosts > /etc/beton/hosts.block
if ! grep -q '^HOOKS=.*beton' /etc/mkinitcpio.conf; then
  sed -i 's/^HOOKS=(\(.*\))/HOOKS=(\1 beton)/' /etc/mkinitcpio.conf
  grep -q '^HOOKS=.*beton' /etc/mkinitcpio.conf || echo 'HOOKS+=(beton)' >> /etc/mkinitcpio.conf
fi
mkinitcpio -P || { echo "mkinitcpio не собрался — дальше нельзя"; exit 1; }
# Юнит нужен был только для упаковки в initramfs — в живой системе ему делать
# нечего (ConditionPath всё равно бы пропустил, но чище убрать).
rm -f /etc/systemd/system/beton-restore.service
systemctl daemon-reload 2>/dev/null || true
echo "initramfs с бетоном собран"
rm -rf /var/lib/sbctl
sbctl create-keys || { echo "create-keys не удался"; exit 1; }
SBKEY=/var/lib/sbctl/keys/db/db.key
SBCERT=/var/lib/sbctl/keys/db/db.pem
[ -f "$SBKEY" ] && [ -f "$SBCERT" ] || { echo "нет ключей sbctl"; exit 1; }
echo "ключ создан (будет уничтожен в конце)"

echo "== UKI (микрокод — только если есть) =="
# без head в пайпе: под pipefail SIGPIPE от head роняет скрипт (поймано в VM).
KVER=$(ls /usr/lib/modules); KVER=${KVER%%$'\n'*}
UCODE=""
[ -f /boot/amd-ucode.img ] && UCODE="--initrd=/boot/amd-ucode.img"
[ -f /boot/intel-ucode.img ] && UCODE="--initrd=/boot/intel-ucode.img"
# shellcheck disable=SC2086
ukify build --linux="/usr/lib/modules/$KVER/vmlinuz" \
  $UCODE --initrd="/boot/initramfs-linux.img" \
  --cmdline="root=LABEL=BETONROOT rw console=ttyS0,115200n8 beton.final=1" \
  --output="$WORK/beton.efi"
echo "UKI собран: $WORK/beton.efi"

echo "== подпись ключом sbctl (в WORK, ESP тронем только после enroll) =="
# Порядок — защита от полусостояния: ESP перезаписываем ЛИШЬ после успеха enroll,
# иначе первая запись BootOrder указывает на образ без заведенного ключа.
sbsign --key "$SBKEY" --cert "$SBCERT" \
  --output "$WORK/beton-signed.efi" "$WORK/beton.efi"
sbverify --cert "$SBCERT" "$WORK/beton-signed.efi"
echo "подпись сошлась"

echo "== enroll custom-ключей (REVIEW: только Setup Mode в VM!) =="
# --tpm-eventlog: в VM без TPM фиксирует отсутствие OptionROM; железо — по FAQ sbctl.
sbctl enroll-keys --custom --tpm-eventlog \
  || { echo "enroll не удался — дальше нельзя"; exit 1; }

echo "== кладём подписанный UKI в ESP =="
cp "$WORK/beton-signed.efi" "/boot/EFI/BOOT/beton-final.efi"
sbverify --cert "$SBCERT" "/boot/EFI/BOOT/beton-final.efi"
echo "UKI на месте и проверен"

echo "== загрузочная запись на подписанный UKI (best-effort) =="
# Блок не роняет церемонию: fallback — выбор beton-final.efi в Boot Menu.
if command -v efibootmgr >/dev/null 2>&1; then
  ESP_SRC=$(findmnt -no SOURCE /boot 2>/dev/null) || ESP_SRC=""
  ESP_DISK=""
  ESP_PART=""
  if [ -n "$ESP_SRC" ]; then
    ESP_BASE="$(basename "$(realpath "$ESP_SRC" 2>/dev/null)" 2>/dev/null)" || ESP_BASE=""
    if [ -n "$ESP_BASE" ] && [ -e "/sys/class/block/$ESP_BASE/partition" ]; then
      ESP_DISK="/dev/$(lsblk -no PKNAME "/dev/$ESP_BASE" 2>/dev/null)" || ESP_DISK=""
      ESP_PART="$(cat "/sys/class/block/$ESP_BASE/partition" 2>/dev/null)" || ESP_PART=""
    fi
  fi
  if [ -n "$ESP_DISK" ] && [ -n "$ESP_PART" ]; then
    efibootmgr --create --disk "$ESP_DISK" --part "$ESP_PART" \
      --label beton-final --loader '\EFI\BOOT\beton-final.efi' \
      && efibootmgr -v 2>/dev/null | head -12 || true
  else
    echo "WARN: не разобрал ESP ($ESP_SRC) — выбери beton-final.efi в Boot Menu вручную"
  fi
else
  echo "WARN: нет efibootmgr — выбери beton-final.efi в Boot Menu вручную"
fi
true

echo "== УНИЧТОЖЕНИЕ КЛЮЧЕЙ — точка невозврата =="
find /var/lib/sbctl -type f -exec shred -u -n 3 {} + 2>/dev/null || true
rm -rf /var/lib/sbctl /etc/sbctl
if find / -xdev \( -name "*.key" -o -name "db.pem" \) -path "*sbctl*" 2>/dev/null | grep -q .; then
  echo "ОСТАТКИ КЛЮЧЕЙ — СТОП"; exit 1
fi
echo "ключей больше нет. Переподписать политику нечем."

echo "== FINAL-флаг: revert мёртв =="
touch /etc/beton/FINAL
cp "$WORK/policy/SHA256SUMS" /etc/beton/policy.SHA256SUMS
/usr/local/bin/beton status || ./beton status || true

cat <<'EOF'
Готово. Машина финализирована:
- revert-for-testing отвечает отказом (код 4)
- политика подписана ключом, которого нет
- смена политики/ядра без подписи = отказ загрузки
- снять = сброс прошивки + переустановка; /home цел
Перезагрузи VM через firmware: проверь SecureBoot on и загрузку beton-final.efi.
EOF
