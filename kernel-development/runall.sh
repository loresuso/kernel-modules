#!/bin/sh 
set -e
sudo mount ./debian-rootfs/example.img -t ext4 /mnt/example
sudo find /home/lore/MasterThesis/kernel-development/attacks-poc -name '*.ko' -exec cp "{}" /mnt/example/root  \;
sudo find /home/lore/MasterThesis/kernel-development/fx-module -name '*.ko' -exec cp "{}" /mnt/example/root  \;
sudo umount -t ext4 /mnt/example
qemu-system-x86_64 \
    -nographic \
    -device edu \
    -device fx \
    -enable-kvm \
    -kernel ./bzImage \
    -boot c \
    -m 1024M \
    -cpu host \
    -hda ./debian-rootfs/example.img \
    -k it \
    -s \
    -nographic \
    -device e1000,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::5555-:22\
    -append "console=ttyS0 root=/dev/sda rw acpi=off nokaslr" \
