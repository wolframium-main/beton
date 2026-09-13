#!/usr/bin/env bash
# make-vm.sh — build the Arch guest image for beton tests. Via pkexec ONLY.
# Touches exactly: $VM_DIR/beton-vm.raw and /mnt/beton-vm. Host system unchanged.
set -euo pipefail

VM_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="$VM_DIR/beton-vm.raw"
MNT="/mnt/beton-vm"
IMG_SIZE="25G"
HOST_USER="wolframium"

[[ $EUID -eq 0 ]] || { echo "run via pkexec only"; exit 2; }
[[ "$IMG" == "$VM_DIR"/*.raw ]] || { echo "guard: weird image path"; exit 2; }
mkdir -p "$VM_DIR" "$MNT"

if [[ ! -f "$IMG" ]]; then
  echo "== image $IMG ($IMG_SIZE)"
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
  echo "== pacstrap (slow, ~5-10 min) =="
  pacstrap -K "$MNT" base linux linux-firmware systemd networkmanager \
    openssh python sudo nftables iproute2
  genfstab -U "$MNT" >> "$MNT/etc/fstab"
fi

echo "== configuring the guest =="
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
# the host script places the key; allow key-auth
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
# Test-VM password. Disposable lab behind NAT with no forwarded ports;
# production never sees this file — the owner sets the password manually.
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

echo "== host SSH key =="
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
echo "OK: image ready: $IMG"
