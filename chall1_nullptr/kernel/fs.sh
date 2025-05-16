#!/bin/sh

set -x

if [ ! -d "core" ]; then
        cp rootfs.cpio rootfs.cpio.bak
        mkdir core
        cd core 
        cpio -idmv < ../rootfs.cpio
        cd ..
fi

# gcc -static exp.c -o exp
# cp exp ./core/home/ctf/exp
cd core
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..
# ./run.sh