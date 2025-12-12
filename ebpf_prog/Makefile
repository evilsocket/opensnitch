# OpenSnitch - 2023
#
# On Debian based distros we need the following 2 directories.
# Otherwise, just use the kernel headers from the kernel sources.
#

KERNEL_VER = $(shell ls -d /lib/modules/*/source | sort | tail -1 | cut -d/ -f4)
KERNEL_DIR = /lib/modules/$(KERNEL_VER)/source
CC = clang
LLC = llc

# Find all .c files and create a list of corresponding .o targets.
SRC_FILES := $(wildcard *.c)
BPF_TARGETS := $(SRC_FILES:.c=.o)

# 'always-y' tells kbuild to compile our BPF targets.
always-y := $(BPF_TARGETS)

# Add extra compiler flags. We add flags to suppress warnings that
# originate from the kernel headers themselves or are common style issues.
ccflags-y := \
	-g -O2 \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-Wno-duplicate-decl-specifier \
	-Wno-enum-enum-conversion \
	-Wno-missing-prototypes

# List of gcc-specific flags from your log that clang 20 does not understand.
GCC_ONLY_FLAGS := \
	-mpreferred-stack-boundary=3 \
	-mindirect-branch=thunk-extern \
	-mindirect-branch-register \
	-mrecord-mcount \
	-fno-allow-store-data-races \
	-fmin-function-alignment=16 \
	-fconserve-stack

# For each of our BPF object files, remove the incompatible gcc flags.
$(foreach bpf_obj,$(BPF_TARGETS),$(eval CFLAGS_REMOVE_$(bpf_obj) = $(GCC_ONLY_FLAGS)))

# Standard targets for an external module Makefile.
all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) CC=$(CC)

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

.PHONY: all clean
