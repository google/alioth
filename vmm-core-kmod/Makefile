# SPDX-License-Identifier: GPL-2.0
# Out-of-tree Makefile for `airlock.ko` (`vmm-core-kmod/`).
# Usage:
#   make KDIR=/path/to/kernel-build
#   make KDIR=/path/to/kernel-build clean

KMOD_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
KDIR     ?= /lib/modules/$(shell uname -r)/build

.PHONY: all clean

all:
	"$(KMOD_DIR)/build.sh" --kmod-only --kdir "$(KDIR)"

clean:
	$(MAKE) -C "$(KDIR)" M="$(KMOD_DIR)" clean
	rm -f "$(KMOD_DIR)/airlock_rust.blob.o" "$(KMOD_DIR)/airlock_rust.o"
