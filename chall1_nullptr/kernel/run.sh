#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append 'console=ttyS0 debug loglevel=7 oops=panic panic=-1 nokaslr' \
    -netdev user,id=net \
    -device e1000,netdev=net \
    -no-reboot \
    -monitor /dev/null \
    -cpu qemu64 \
    -smp cores=2,threads=1 \
    -nographic
