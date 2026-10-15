# SPDX-License-Identifier: Apache-2.0
# secdebug build
#
# KPM build requires a KernelPatch/KPatch-Next source tree that provides the
# headers under kernel/. Userspace SDK checks can be built on a normal host.

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

CLANG ?= clang
LLD ?= ld.lld
PYTHON ?= python3
CC ?= cc

KP_DIR ?= ../KernelPatch
BUILD_DIR ?= build
TARGET_ARCH ?= aarch64-none-elf
# Optional code-scheduling preference. Unlike -mcpu=<device>, -mtune keeps
# the generic ARM64 ISA, so a big.LITTLE system can still run all instructions.
# Leave generic unless a real target has been profiled.
KPM_TUNE ?= generic

KPM_CFLAGS := --target=$(TARGET_ARCH) -mcpu=generic -std=gnu11 -O2 -Wall -Wextra \
              -fno-builtin -fno-stack-protector -fno-common \
              -ffreestanding -fno-strict-aliasing -fno-PIE -fno-pic \
              -mgeneral-regs-only -mno-outline-atomics -MMD -MP
ifneq ($(strip $(KPM_TUNE)),generic)
KPM_CFLAGS += -mtune=$(KPM_TUNE)
endif

INCLUDE_DIRS := . include $(KP_DIR)/kernel/include $(KP_DIR)/kernel/patch/include \
                $(KP_DIR)/kernel/linux/include $(KP_DIR)/kernel/linux/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

SRCS := src/secdebug_core.c src/secdebug_mem.c src/secdebug_session.c src/secdebug_hwbp.c
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)
KPM := $(BUILD_DIR)/secdebug.kpm
BUILD_CONFIG := $(BUILD_DIR)/build-config.json
BUILD_METADATA := $(BUILD_DIR)/BUILD-METADATA.txt
CLIENT_TEST := $(BUILD_DIR)/client/test_secdebug
PROTO_TEST := $(BUILD_DIR)/tests/proto_layout
CLIENT_PROTOCOL_TEST := $(BUILD_DIR)/tests/client_protocol
CLIENT_SESSION_TEST := $(BUILD_DIR)/tests/client_session
SESSION_STATE_TEST := $(BUILD_DIR)/tests/session_state
PERF_ABI_TEST := $(BUILD_DIR)/tests/perf_attr_layout

# Releasing a high-privilege KPM against an unreviewed loader is unsafe.
# These inputs intentionally apply only to the actual KPM build, not tests.
HOST_CONTRACT_ACK ?=
HOST_COMMIT ?=
TARGET_PAGE_SHIFT ?=
SECDEBUG_FOLL_FORCE ?=
SECDEBUG_PERF_PENDING_OFFSET ?=
ifneq ($(strip $(TARGET_PAGE_SHIFT)),)
KPM_CFLAGS += -DSECDEBUG_TARGET_PAGE_SHIFT=$(TARGET_PAGE_SHIFT)
endif
ifneq ($(strip $(SECDEBUG_FOLL_FORCE)),)
KPM_CFLAGS += -DSECDEBUG_FOLL_FORCE=$(SECDEBUG_FOLL_FORCE)
endif
ifneq ($(strip $(SECDEBUG_PERF_PENDING_OFFSET)),)
KPM_CFLAGS += -DSECDEBUG_PERF_PENDING_OFFSET=$(SECDEBUG_PERF_PENDING_OFFSET)
endif

# Export values directly: the fingerprint helper never evals shell fragments.
export HOST_CONTRACT_ACK
export KP_DIR HOST_COMMIT TARGET_ARCH TARGET_PAGE_SHIFT SECDEBUG_FOLL_FORCE KPM_TUNE
export SECDEBUG_PERF_PENDING_OFFSET KPM_CFLAGS INCLUDE_FLAGS CLANG LLD

.PHONY: check-host-contract
check-host-contract:
	$(PYTHON) scripts/host_contract.py --build

all: $(KPM) $(BUILD_METADATA)

# The helper preserves mtime when content is unchanged. A normal dependency
# invalidates every object when flags, host patch state or toolchain change.
.PHONY: FORCE
FORCE:

$(BUILD_CONFIG): scripts/host_contract.py host_patches/hosts.json $(wildcard host_patches/*.patch) scripts/build_config.py include/secdebug_proto.h Makefile FORCE | check-host-contract
	@mkdir -p $(@D)
	$(PYTHON) scripts/build_config.py "$@"

$(BUILD_DIR)/%.o: %.c $(BUILD_CONFIG) | check-host-contract
	@mkdir -p $(@D)
	$(CLANG) $(KPM_CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

# Grouped targets require GNU make >= 4.3. Missing either member rebuilds the
# pair. Rejected temporary ELFs are never published under the final filename.
$(KPM) $(BUILD_METADATA) &: $(OBJS) $(BUILD_CONFIG) scripts/link_kpm.py scripts/verify_symbols.py
	$(PYTHON) scripts/link_kpm.py --config "$(BUILD_CONFIG)" \
	  --output "$(KPM)" --metadata "$(BUILD_METADATA)" $(OBJS)

client: $(CLIENT_TEST)

$(CLIENT_TEST): client/test_secdebug.c client/libsecdebug.c client/libsecdebug.h client/secdebug_host_abi.h include/secdebug_proto.h
	@mkdir -p $(@D)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Iinclude -Iclient \
		client/test_secdebug.c client/libsecdebug.c -o $@

$(PROTO_TEST): tests/proto_layout.c include/secdebug_proto.h
	@mkdir -p $(@D)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Iinclude $< -o $@

$(CLIENT_PROTOCOL_TEST): tests/client_protocol.c client/libsecdebug.c client/libsecdebug.h client/secdebug_host_abi.h include/secdebug_proto.h
	@mkdir -p $(@D)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Iinclude -Iclient $< -o $@

$(CLIENT_SESSION_TEST): tests/client_session.c client/libsecdebug.c client/libsecdebug.h client/secdebug_host_abi.h include/secdebug_proto.h
	@mkdir -p $(@D)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Iinclude -Iclient $< -o $@

$(SESSION_STATE_TEST): tests/session_state.c src/secdebug_session.c include/secdebug_internal.h include/secdebug_proto.h
	@mkdir -p $(@D)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Itests/stub_host -Iinclude $< -o $@

$(PERF_ABI_TEST): tests/perf_attr_layout.c include/secdebug_perf_abi.h include/secdebug_proto.h
	@mkdir -p $(@D)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -DSECDEBUG_VERIFY_TARGET_PERF_ABI -Iinclude $< -o $@

check: $(CLIENT_TEST) $(PROTO_TEST) $(CLIENT_PROTOCOL_TEST) $(CLIENT_SESSION_TEST) $(SESSION_STATE_TEST) $(PERF_ABI_TEST)
	$(PROTO_TEST)
	$(CLIENT_PROTOCOL_TEST)
	$(CLIENT_SESSION_TEST)
	$(SESSION_STATE_TEST)
	$(PERF_ABI_TEST)
	$(PYTHON) tests/source_invariants.py
	$(PYTHON) tests/config_safety.py
	$(PYTHON) tests/host_patch_bounds.py
	$(PYTHON) tests/host_patch_apply.py
	$(PYTHON) tests/host_lifecycle.py
	$(PYTHON) tests/runtime_regressions.py
	$(PYTHON) tests/build_regressions.py

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all client check clean check-stub sanitize ubsan package

check-stub:
	sh scripts/check_stub_kpm.sh

sanitize:
	sh scripts/run_sanitizers.sh
	SECDEBUG_TEST_SANITIZE=1 CC=$(CLANG) $(PYTHON) tests/host_patch_bounds.py
	SECDEBUG_TEST_SANITIZERS=address,undefined CC=$(CLANG) $(PYTHON) tests/runtime_regressions.py
	SECDEBUG_TEST_SANITIZERS=address,undefined CC=$(CLANG) $(PYTHON) tests/host_lifecycle.py

ubsan:
	SANITIZERS=undefined CLANG=$(CC) sh scripts/run_sanitizers.sh
	SECDEBUG_TEST_SANITIZERS=undefined CC=$(CC) $(PYTHON) tests/host_patch_bounds.py
	SECDEBUG_TEST_SANITIZERS=undefined CC=$(CC) $(PYTHON) tests/runtime_regressions.py
	SECDEBUG_TEST_SANITIZERS=undefined CC=$(CC) $(PYTHON) tests/host_lifecycle.py

# Reproducible source ZIP: excludes all .git/history/build files and retains
# POSIX executable mode bits on scripts even when unpacked on another host.
package:
	$(PYTHON) scripts/package_source.py --output dist/SecDebug-source.zip

-include $(DEPS)
