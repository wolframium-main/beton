#!/usr/bin/env bash
# make-vm.sh — сборка гостевого Arch-образа для тестов beton. ТОЛЬКО через pkexec.
# Трогает ровно: $VM_DIR/beton-vm.raw и /mnt/beton-vm. Хост-систему не меняет.
set -euo pipefail

VM_DIR="/home/wolframium/Проекты/beton/vm"
IMG="$VM_DIR/beton-vm.raw"
MNT="/mnt/beton-vm"
IMG_SIZE="25G"
HOST_USER="wolframium"

[[ $EUID -eq 0 ]] || { echo "запуск только через pkexec"; exit 2; }
[[ "$IMG" == /home/wolframium/Проекты/beton/vm/*.raw ]] || { echo "guard: странный путь образа"; exit 2; }
mkdir -p "$VM_DIR" "$MNT"

if [[ ! -f "$IMG" ]]; then
  echo "== образ $IMG ($IMG_SIZE)"
  truncate -s "$IMG_SIZE" "$IMG"
  sfdisk "$IMG" <<'EOF'
label: gpt
,512M,U
,
EOF
fi

echo "== loop =="
LOOP=$(losetup --show -Pf "$IMG")
ESP="${LOOP}p1"; ROOT="${LOOP}p2"
cleanup() { umount -R "$MNT" 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true; }
trap cleanup EXIT

if ! blkid -o value -s LABEL "$ROOT" 2>/dev/null | grep -q BETONROOT; then
  echo "== mkfs =="
  mkfs.fat -F32 -n BETONESP "$ESP"
  mkfs.ext4 -q -L BETONROOT "$ROOT"
fi

echo "== mount =="
mount "$ROOT" "$MNT"
mkdir -p "$MNT/boot"
mount "$ESP" "$MNT/boot"

if [[ ! -f "$MNT/etc/arch-release" && ! -f "$MNT/etc/os-release" ]]; then
  echo "== pacstrap (долго, ~5-10 мин) =="
  pacstrap -K "$MNT" base linux linux-firmware systemd networkmanager \
    openssh python sudo nftables iproute2
  genfstab -U "$MNT" >> "$MNT/etc/fstab"
fi

echo "== настройка гостя =="
arch-chroot "$MNT" bash -s <<'EOF'
set -e
echo beton-vm > /etc/hostname
ln -sf /usr/share/zoneinfo/Europe/Moscow /etc/localtime
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen >/dev/null 2>&1 || true
echo "LANG=en_US.UTF-8" > /etc/locale.conf
echo "KEYMAP=us" > /etc/vconsole.conf
systemctl enable sshd NetworkManager serial-getty@ttyS0 >/dev/null
mkdir -p /root/.ssh && chmod 700 /root/.ssh
# ключ положит хост-скрипт; разрешаем key-auth
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
echo "root:beton" | chpasswd
bootctl install --esp-path=/boot >/dev/null
cat > /boot/loader/loader.conf <<'LOADER'
default beton
timeout 1
console-mode max
LOADER
cat > /boot/loader/entries/beton.conf <<'ENTRY'
title   Beton VM
linux   /vmlinuz-linux
initrd  /initramfs-linux.img
options root=LABEL=BETONROOT rw console=ttyS0,115200n8
ENTRY
EOF

echo "== SSH-ключ хоста =="
if [[ ! -f "$VM_DIR/id_ed25519" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$VM_DIR/id_ed25519" -C beton-vm -q
fi
cp "$VM_DIR/id_ed25519.pub" "$MNT/root/.ssh/authorized_keys"
chmod 600 "$MNT/root/.ssh/authorized_keys"

sync
umount -Rl "$MNT" || true
sleep 1
for i in 1 2 3 4 5; do losetup -d "$LOOP" 2>/dev/null && break; sleep 1; done
trap - EXIT
chown "$HOST_USER:$HOST_USER" "$IMG" "$VM_DIR/id_ed25519" "$VM_DIR/id_ed25519.pub" 2>/dev/null || true
chmod 600 "$VM_DIR/id_ed25519" 2>/dev/null || true
echo "OK: образ готов: $IMG"
