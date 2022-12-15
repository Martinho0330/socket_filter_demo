#! /bin/bash
set -x
target="$1"
filename="socket.c"
if [ "$target" == "test" ]; then
  filename="socket_test.c"
fi
clang -fopenmp -I/usr/src/linux-headers-4.9.0-141-custom/arch/x86/include  -I/usr/src/linux-headers-4.9.0-141-custom/arch/x86/include/generated/uapi  -I/usr/src/linux-headers-4.9.0-141-custom/arch/x86/include/generated  -I/usr/src/linux-headers-4.9.0-141-custom/include  -I/usr/src/linux-headers-4.9.0-141-custom/arch/x86/include/uapi  -I/usr/src/linux-headers-4.9.0-141-custom/include/uapi  -I/usr/src/linux-headers-4.9.0-141-custom/include/generated/uapi  -include /usr/src/linux-headers-4.9.0-141-custom/include/linux/kconfig.h  -I./kern -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include   -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign  -Wall -Wno-compare-distinct-pointer-types -O2 -emit-llvm   -DKBUILD_MODNAME="xxx_ebpf_yy"   -c kern/$filename -o - | llc  -march=bpf -filetype=obj  -o bpf_bpfel.o