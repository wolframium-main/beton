#!/bin/sh
# beton-restore: выполняется юнитом beton-restore.service в initramfs
# (After=sysroot.mount, Before=initrd-switch-root.target).
# Доливает hosts.block в /sysroot/etc/hosts. Только POSIX.
echo "beton-restore: start" > /dev/kmsg 2>/dev/null || true
if [ ! -f /etc/beton/hosts.block ]; then
    echo "beton-restore: no hosts.block" > /dev/kmsg 2>/dev/null || true
    exit 0
fi
if grep -q ">>> BETON >>>" /sysroot/etc/hosts 2>/dev/null; then
    echo "beton-restore: already present" > /dev/kmsg 2>/dev/null || true
    exit 0
fi
mount -o remount,rw /sysroot 2>/dev/null || true
if cat /etc/beton/hosts.block >> /sysroot/etc/hosts 2>/dev/null; then
    echo "beton-restore: restored" > /dev/kmsg 2>/dev/null || true
else
    echo "beton-restore: APPEND FAILED" > /dev/kmsg 2>/dev/null || true
fi
exit 0
