# OpenSnitch - 2026
#
# On Debian based distros we need the following 2 directories.
# Otherwise, just use the kernel headers from the kernel sources.
#
KERNEL_VER ?= $(shell find /lib/modules/* -maxdepth 1 \( -type d -o -type l \) \( -name "build" -o -name "source" \) | sort | tail -1 | cut -d/ -f4)
ifeq ($(KERNEL_VER),)
	$(error KERNEL_VER is missing.)
endif
KERNEL_DIR ?= $(shell find /lib/modules/$(KERNEL_VER) -maxdepth 1 \( -type d -o -type l \) \( -name "build" -o -name "source" \) | sort | tail -1)
ifeq ($(KERNEL_DIR),)
	$(error KERNEL_DIR is missing.)
endif
KERNEL_HEADERS ?= /usr/src/linux-headers-$(KERNEL_VER)/
# use KERNEL_ARCH, as ARCH is being changed
KERNEL_ARCH ?= $(shell uname -m)
KERNEL_6_19_CHECK = $(shell expr "$(KERNEL_VER)" \>= "6.19")
CC = clang
LLC ?= llc
ARCH ?= $(shell uname -m)

# as in /usr/src/linux-headers-*/arch/
# TODO: extract correctly the archs, and add more if needed.
ifeq ($(ARCH),x86_64)
	ARCH := x86
else ifeq ($(ARCH),i686)
	ARCH := x86
else ifeq ($(ARCH),armv7l)
	ARCH := arm
else ifeq ($(ARCH),armv8l)
	ARCH := arm
else ifeq ($(ARCH),aarch64)
	ARCH := arm64
else ifeq ($(ARCH),loongarch64)
	ARCH := loongarch
else ifeq ($(ARCH),riscv64)
	ARCH := riscv
else ifeq ($(ARCH),s390x)
	ARCH := s390
endif

# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++#tldr-what-compiler-options-should-i-use
EXTRA_FLAGS = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3

ifeq ($(ARCH),arm)
	# on previous archs, it fails with "SMP not supported on pre-ARMv6"
	EXTRA_FLAGS += -D__LINUX_ARM_ARCH__=7
endif
# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++#enable-control-flow-and-branch-protection-against-return-oriented-programming-and-jump-oriented-programming-attacks
ifeq ($(KERNEL_ARCH),x86_64)
	EXTRA_FLAGS += -fcf-protection=full
endif
ifeq ($(KERNEL_ARCH),aarch64)
	EXTRA_FLAGS += -mbranch-protection=standard
endif
# https://lore.kernel.org/bpf/20251208130748.68371-1-qmo@kernel.org/
ifeq ($(KERNEL_6_19_CHECK),1)
	EXTRA_FLAGS += -Wno-microsoft-anon-tag -fms-extensions
endif

$(info ebpf_prog build env:)
$(info ARCH           = $(ARCH))
$(info KERNEL_VER     = $(KERNEL_VER))
$(info KERNEL_DIR     = $(KERNEL_DIR))
$(info KERNEL_HEADERS = $(KERNEL_HEADERS))
$(info KERNEL_ARCH    = $(KERNEL_ARCH))
$(info EXTRA_FLAGS    = $(EXTRA_FLAGS))

# opensnitch-scan.c is excluded deliberately, and must stay excluded.
#
# This Makefile compiles against the kernel's own headers with -D__KERNEL__ and
# a long list of -I paths into the kernel tree. The scan module is a portable
# libbpf program: it includes <bpf/bpf_helpers.h>, which is not on those paths,
# so adding it here fails the build of every OTHER module with
# "fatal error: 'bpf/bpf_helpers.h' file not found" -- it is a wildcard, so
# without the exclusion, the file being in this directory would be enough to
# break the existing build, including the upstream CI workflow and
# utils/packaging/build_modules.sh.
#
# It is built by Makefile.scan, which needs no kernel source at all:
# `make -f Makefile.scan`, as utils/packaging/build_modules.sh does.
SCAN_SRC := opensnitch-scan.c
SRC := $(filter-out $(SCAN_SRC),$(wildcard *.c))
BIN := $(SRC:.c=.o)
CFLAGS = -I. \
	-I$(KERNEL_HEADERS)/arch/$(ARCH)/include/generated/ \
	-I$(KERNEL_HEADERS)/include \
	-include $(KERNEL_DIR)/include/linux/kconfig.h \
	-I$(KERNEL_DIR)/include \
	-I$(KERNEL_DIR)/include/uapi \
	-I$(KERNEL_DIR)/include/generated/uapi \
	-I$(KERNEL_DIR)/arch/$(ARCH)/include \
	-I$(KERNEL_DIR)/arch/$(ARCH)/include/generated \
	-I$(KERNEL_DIR)/arch/$(ARCH)/include/uapi \
	-I$(KERNEL_DIR)/arch/$(ARCH)/include/generated/uapi \
	-I$(KERNEL_DIR)/tools/testing/selftests/bpf/ \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	$(EXTRA_FLAGS) \
	-Wunused \
	-Wno-unused-value \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-fno-stack-protector \
	-g -O2 -emit-llvm

all: $(BIN)

%.bc: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.bc
	$(LLC) -march=bpf -mcpu=generic -filetype=obj -o $@ $<

clean:
	rm -f $(BIN)

.SUFFIXES:
