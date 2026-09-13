#!/usr/bin/env bash
# finalize.sh — IRREVERSIBILITY CEREMONY. VM ONLY. The gate refuses on the host.
#
# What it does: bundles the policy, builds a UKI, signs with a FRESH key,
# verifies the signature, shreds the key, sets the FINAL flag (kills revert).
# After it, removal = firmware reset + reinstall. /home untouched.
#
# Order in the VM (with a snapshot!):
#   1. pacman -S systemd-ukify sbctl sbsigntools cryptsetup (REVIEW: Arch packages)
#   2. Put the VM into Setup Mode, enable SecureBoot (hypervisor settings)
#   3. sudo ./beton block ... && run VM_TESTS.md, write /etc/beton/VM_MATRIX_OK
#   4. echo "I ACCEPT IRREVERSIBILITY $(date -I)" | sudo tee /etc/beton/ALLOW_FINAL
#   5. sudo bash l3/finalize.sh --i-am-sure
set -euo pipefail
cd "$(dirname "$0")/.."

[[ "${1:-}" == "--i-am-sure" ]] || { echo "refusing without --i-am-sure"; exit 2; }
[[ $EUID -eq 0 ]] || { echo "root in VM only"; exit 2; }

echo "== gate =="
python3 l3/gate.py || { echo "gate is red — stop"; exit 1; }

WORK=/root/beton-final
mkdir -p "$WORK"
DOMAINS=$(cat /var/lib/beton/domains.txt | tr '\n' ' ')
echo "== policy: $DOMAINS"

echo "== policy bundle =="
mkdir -p "$WORK/policy"
cp /var/lib/beton/domains.txt "$WORK/policy/"
cp /etc/beton/rules.nft "$WORK/policy/"
python3 ./beton gen-ebpf $DOMAINS --out "$WORK/policy/patterns.h"
sha256sum "$WORK/policy/"* | tee "$WORK/policy/SHA256SUMS"

echo "== early hosts block into initramfs (before UKI!) =="
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p /etc/initcpio/hooks /etc/initcpio/install
cp "$SCRIPT_DIR/mkinitcpio-hook-beton" /etc/initcpio/hooks/beton
cp "$SCRIPT_DIR/mkinitcpio-install-beton" /etc/initcpio/install/beton
cp "$SCRIPT_DIR/beton-restore.sh" /usr/bin/beton-restore
cp "$SCRIPT_DIR/beton-restore.service" /etc/systemd/system/beton-restore.service
chmod 755 /usr/bin/beton-restore
# hosts.block: snapshot of the current section (initramfs pours it before switch_root)
awk '/>>> BETON >>>/,/<<< BETON <<</' /etc/hosts > /etc/beton/hosts.block
if ! grep -q '^HOOKS=.*beton' /etc/mkinitcpio.conf; then
  sed -i 's/^HOOKS=(\(.*\))/HOOKS=(\1 beton)/' /etc/mkinitcpio.conf
  grep -q '^HOOKS=.*beton' /etc/mkinitcpio.conf || echo 'HOOKS+=(beton)' >> /etc/mkinitcpio.conf
fi
mkinitcpio -P || { echo "mkinitcpio failed — cannot continue"; exit 1; }
# The unit was only needed to pack initramfs — nothing for it to do on the live system
# (ConditionPath would skip it anyway, but cleaner to remove).
rm -f /etc/systemd/system/beton-restore.service
systemctl daemon-reload 2>/dev/null || true
echo "initramfs with beton built"
rm -rf /var/lib/sbctl
sbctl create-keys || { echo "create-keys failed"; exit 1; }
SBKEY=/var/lib/sbctl/keys/db/db.key
SBCERT=/var/lib/sbctl/keys/db/db.pem
[ -f "$SBKEY" ] && [ -f "$SBCERT" ] || { echo "no sbctl keys"; exit 1; }
echo "key created (will be destroyed at the end)"

echo "== UKI (microcode — only if present) =="
# no head in pipes: under pipefail its SIGPIPE kills the script (caught in VM).
KVER=$(ls /usr/lib/modules); KVER=${KVER%%$'\n'*}
UCODE=""
[ -f /boot/amd-ucode.img ] && UCODE="--initrd=/boot/amd-ucode.img"
[ -f /boot/intel-ucode.img ] && UCODE="--initrd=/boot/intel-ucode.img"
# shellcheck disable=SC2086
ukify build --linux="/usr/lib/modules/$KVER/vmlinuz" \
  $UCODE --initrd="/boot/initramfs-linux.img" \
  --cmdline="root=LABEL=BETONROOT rw console=ttyS0,115200n8 beton.final=1" \
  --output="$WORK/beton.efi"
echo "UKI built: $WORK/beton.efi"

echo "== sign with the sbctl key (in WORK, ESP touched only after enroll) =="
# Order protects against half-states: ESP is overwritten ONLY after enroll success,
# otherwise the first BootOrder entry points at an image with no enrolled key.
sbsign --key "$SBKEY" --cert "$SBCERT" \
  --output "$WORK/beton-signed.efi" "$WORK/beton.efi"
sbverify --cert "$SBCERT" "$WORK/beton-signed.efi"
echo "signature checks out"

echo "== enroll custom keys (REVIEW: Setup Mode in VM only!) =="
# --tpm-eventlog: in a TPM-less VM records the absence of OptionROM; hardware — see sbctl FAQ.
sbctl enroll-keys --custom --tpm-eventlog \
  || { echo "enroll failed — cannot continue"; exit 1; }

echo "== placing the signed UKI into ESP =="
cp "$WORK/beton-signed.efi" "/boot/EFI/BOOT/beton-final.efi"
sbverify --cert "$SBCERT" "/boot/EFI/BOOT/beton-final.efi"
echo "UKI in place and verified"

echo "== boot entry for the signed UKI (best-effort) =="
# The block never fails the ceremony: fallback is picking beton-final.efi in the Boot Menu.
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
    echo "WARN: could not parse ESP ($ESP_SRC) — pick beton-final.efi in the Boot Menu manually"
  fi
else
  echo "WARN: no efibootmgr — pick beton-final.efi in the Boot Menu manually"
fi
true

echo "== DESTROYING THE KEYS — point of no return =="
find /var/lib/sbctl -type f -exec shred -u -n 3 {} + 2>/dev/null || true
rm -rf /var/lib/sbctl /etc/sbctl
if find / -xdev \( -name "*.key" -o -name "db.pem" \) -path "*sbctl*" 2>/dev/null | grep -q .; then
  echo "KEY LEFTOVERS — STOP"; exit 1
fi
echo "no keys left. Nothing to re-sign the policy with."

echo "== FINAL flag: revert is dead =="
touch /etc/beton/FINAL
cp "$WORK/policy/SHA256SUMS" /etc/beton/policy.SHA256SUMS
/usr/local/bin/beton status || ./beton status || true

cat <<'EOF'
Done. Machine finalized:
- revert-for-testing answers with refusal (code 4)
- policy signed with a key that no longer exists
- policy/kernel change without signature = boot refusal
- removal = firmware reset + reinstall; /home intact
Reboot the VM via firmware: verify SecureBoot on and beton-final.efi boot.
EOF
