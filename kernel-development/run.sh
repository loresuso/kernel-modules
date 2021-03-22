#!/bin/sh
qemu-system-x86_64 \
    -device edu \
    -device fx \
    -enable-kvm \
    -kernel ./bzImage \
    -boot c \
    -m 1024M \
    -cpu host \
    -hda ./rootfs.ext2 \
    -k it \
    -s \
    -monitor stdio \
    -append "root=/dev/sda rw acpi=off nokaslr" \
