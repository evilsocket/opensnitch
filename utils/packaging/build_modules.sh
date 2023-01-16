#!/bin/sh
#
# opensnitch - 2022-2023
#
echo """

  Dependencies needed to compile the eBPF modules:
  sudo apt install -y wget flex bison ca-certificates wget python3 rsync bc libssl-dev clang llvm libelf-dev libzip-dev git libpcap-dev
  ---
"""

kernel_version=$(uname -r | cut -d. -f1,2)
if [ ! -z $1 ]; then
    kernel_version=$1
fi

kernel_sources="v${kernel_version}.tar.gz"

if [ -f "${kernel_sources}" ]; then
    echo -n "[i] Deleting previous kernel sources ${kernel_sources}: "
    rm -f ${kernel_sources} && echo "OK" || echo "ERROR"
fi
echo "[+] Downloading kernel sources:"
wget -nv --show-progress https://github.com/torvalds/linux/archive/${kernel_sources} 1>/dev/null
echo

if [ -d "linux-${kernel_version}/" ]; then
    echo -n "[i] Deleting previous kernel sources dir linux-${kernel_version}/: "
    rm -rf linux-${kernel_version}/ && echo "OK" || echo "ERROR"
fi
echo -n "[+] Uncompressing kernel sources: "
tar -xf v${kernel_version}.tar.gz && echo "OK" || echo "ERROR"

echo "[+] Patching kernel sources"
if [ "${ARCH}" == "arm" -o "${ARCH}" == "arm64" ]; then
	patch linux-${kernel_version}/arch/arm/include/asm/unified.h < ebpf_prog/arm-clang-asm-fix.patch
else
	patch linux-${kernel_version}/tools/lib/bpf/bpf_helpers.h < ebpf_prog/file.patch
fi

cp ebpf_prog/opensnitch*.c ebpf_prog/common.h ebpf_prog/common_defs.h ebpf_prog/Makefile linux-${kernel_version}/samples/bpf

echo -n "[+] Preparing kernel sources... (1-2 minutes): "
echo -n "."
cd linux-${kernel_version} && yes "" | make oldconfig 1>/dev/null
echo -n "."
make prepare 1>/dev/null
echo -n "."
make headers_install 1>/dev/null
echo " DONE"

echo "[+] Compiling eBPF modules..."
cd samples/bpf && make 1>/dev/null
# objdump -h opensnitch.o #you should see many section, number 1 should be called kprobe/tcp_v4_connect

if [ ! -d ../../../ebpf_prog/modules/ ]; then
    mkdir ../../../ebpf_prog/modules/
fi
cp opensnitch*o ../../../ebpf_prog/modules/
cd ../../../
llvm-strip -g ebpf_prog/modules/opensnitch.o #remove debug info

if [ -f ebpf_prog/modules/opensnitch.o ]; then
    echo
    ls ebpf_prog/modules/*.o
    echo -e "\n * eBPF modules compiled. Now you can copy the *.o files to /etc/opensnitchd/ and restart the daemon\n"
fi
