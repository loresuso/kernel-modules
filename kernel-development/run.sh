#!/bin/sh
qemu-system-x86_64 \
    -device edu \
    -enable-kvm \
    -kernel ./bzImage \
    -boot c \
    -m 1024M \
    -hda ./rootfs.ext2 \
    -append "root=/dev/sda rw acpi=off nokaslr" 
