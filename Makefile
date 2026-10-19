.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-loader.elf
# Probe payloads live in source/ for historical reasons, but each has its own main() and is
# built INDIVIDUALLY with the SDK wrapper. Linking them into the loader fails with duplicate
# symbol: main. Exclude them here rather than moving the files (the build artifacts and the
# handoff notes reference these paths).
PROBE_SRC := source/efimeta_probe.c source/oracle_probe.c source/physmem_probe.c \
             source/propro_probe.c source/propro_probe2.c source/viola_probe.c \
             source/wakepa_probe.c source/wakepa_probe_1160.c source/wakepa_probe_1360.c
SRC := $(filter-out $(PROBE_SRC),$(wildcard source/*.c))
OBJS := $(SRC:.c=.o)

# EXTRA_CFLAGS reaches the shellcode sub-makes through their own Makefiles, but used to stop
# there: a -D passed on the command line silently had no effect on source/*.c, and the build
# came out byte-identical to one without it. Appended here so loader-side flags work too
# (e.g. -DPS5_VBIOS_OVERRIDE).
CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel $(EXTRA_CFLAGS)
LDFLAGS :=

SC_HV_H := shellcode_hv/shellcode_hv.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h
SC_AP_H := shellcode_ap/shellcode_ap.h

# These used to have NO prerequisites, so once the .h existed `make` considered it up to date and
# silently linked the OLD blob after a shellcode edit. The byte-blob is regenerated only when a
# shellcode source changes, which is exactly what the prerequisites below now express.
SC_HV_SRC   := $(wildcard shellcode_hv/*.c shellcode_hv/*.S shellcode_hv/*.h shellcode_hv/*.ld)
SC_K_SRC    := $(wildcard shellcode_kernel/*.c shellcode_kernel/*.S shellcode_kernel/*.h shellcode_kernel/*.ld)
SC_AP_SRC   := $(wildcard shellcode_ap/*.c shellcode_ap/*.S shellcode_ap/*.h shellcode_ap/*.ld)

all: $(SC_HV_H) $(SC_K_H) $(SC_AP_H) $(BIN)

$(SC_HV_H): $(SC_HV_SRC)
	$(MAKE) -C shellcode_hv

$(SC_K_H): $(SC_K_SRC)
	$(MAKE) -C shellcode_kernel

# The 13.x AP payload, built with the host toolchain (freestanding, linked at 0) rather than
# the SDK, because it is a position-independent blob copied to a physical page at runtime.
$(SC_AP_H):
	$(MAKE) -C shellcode_ap

# The loader's own objects embed the shellcode blobs through the generated .h files, but had no
# header prerequisites -- so regenerating a blob (e.g. for an op-mask bisect build) would NOT
# recompile them and `make` would relink the OLD blob. That silently makes every bisect probe lie.
$(OBJS): %.o: %.c $(wildcard include/*.h) $(SC_HV_H) $(SC_K_H) $(SC_AP_H)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_ap clean
