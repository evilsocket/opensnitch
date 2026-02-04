# OpenSnitch eBPF - CO-RE (Compile Once, Run Everywhere) Build
#
# This Makefile builds eBPF programs with CO-RE support.
# CO-RE programs use BTF relocations resolved at load time.
#
# Requirements:
#   - clang with BPF target support (or bpf-unknown-none-gcc--not recommended)
#   - vmlinux.h (in bpf_headers/)
#   - libbpf (for bpf_helpers.h, bpf_tracing.h, bpf_core_read.h)

# Clang with BPF target
CC = clang
CFLAGS_TARGET = -target bpf

# GCC BPF cross-compiler (alternative)
#CC = bpf-unknown-none-gcc
#CFLAGS_TARGET = -gbtf
#OBJCOPY = bpf-unknown-none-objcopy

# Target architecture for __TARGET_ARCH_xxx define
# Override with: make ARCH=arm64
ARCH ?= $(shell uname -m)

# Normalize architecture names
ifeq ($(ARCH),x86_64)
	ARCH := x86
else ifeq ($(ARCH),i686)
	ARCH := i386
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

# Get libbpf include path from pkg-config
# pkg-config never implemented proper cross-compilation support (--host was
# proposed in 2005 but never merged). It filters -I paths that match
# C_INCLUDE_PATH, but BPF cross-compiler uses CROSS_C_INCLUDE_PATH instead.
# PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 disables this filtering.
LIBBPF_CFLAGS := $(shell PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --cflags libbpf)

# Source files
SRC = opensnitch.c opensnitch-procs.c opensnitch-dns.c
BIN = $(SRC:.c=.o)

# Compiler flags for CO-RE BPF programs
CFLAGS = -I. \
	$(CFLAGS_TARGET) \
	$(LIBBPF_CFLAGS) \
	-Ibpf_headers \
	-D__KERNEL__ \
	-D__BPF_TRACING__ \
	-D__TARGET_ARCH_$(ARCH) \
	-Wall \
	-Wno-unused-value \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-fno-stack-protector \
	-g -O2

all: $(BIN)

%.o: %.c bpf_headers/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@
# GCC BPF: strip .BTF.ext section (incompatible with cilium/ebpf)
#	$(OBJCOPY) --remove-section=.BTF.ext --remove-section=.rel.BTF.ext $@

clean:
	rm -f $(BIN)

.PHONY: all clean
