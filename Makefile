.PHONY: all clean shellcode

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-loader.elf
SRC := $(wildcard source/*.c)
OBJS := $(SRC:.c=.o)

CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel
LDFLAGS :=

SC_0607_H     := shellcode_0607/shellcode_0607.h
SC_HV_H       := shellcode_hv/shellcode_hv.h
SC_K_H        := shellcode_kernel/shellcode_kernel.h
SC_K_13XX_H   := shellcode_kernel_13xx/shellcode_kernel_13xx.h
SC_K_1160_H   := shellcode_kernel_1160/shellcode_kernel_1160.h
SC_BREAK_HV_H := shellcode_break_hv/break_hv.h

all: $(BIN)

# Generate shellcode headers in dependency order.
shellcode: $(SC_0607_H) $(SC_HV_H) $(SC_BREAK_HV_H) $(SC_K_H) \
           $(SC_K_13XX_H) $(SC_K_1160_H)

$(SC_0607_H):
	$(MAKE) -C shellcode_0607

$(SC_HV_H):
	$(MAKE) -C shellcode_hv

$(SC_BREAK_HV_H):
	$(MAKE) -C shellcode_break_hv

$(SC_K_H): $(SC_HV_H)
	$(MAKE) -C shellcode_kernel

$(SC_K_13XX_H): $(SC_HV_H) shellcode_kernel/main.c \
                shellcode_kernel/boot_linux.c \
                shellcode_kernel/utils.c \
                shellcode_kernel/main.h \
                shellcode_kernel/boot_linux.h \
                shellcode_kernel/utils.h \
                shellcode_kernel/shellcode_kernel_args.h \
                shellcode_kernel/linker.ld \
                include/config.h include/linux.h \
                shellcode_kernel_13xx/Makefile
	$(MAKE) -C shellcode_kernel_13xx

$(SC_K_1160_H): $(SC_HV_H) shellcode_kernel/main.c \
                shellcode_kernel/boot_linux.c \
                shellcode_kernel/utils.c \
                shellcode_kernel/main.h \
                shellcode_kernel/boot_linux.h \
                shellcode_kernel/utils.h \
                shellcode_kernel/shellcode_kernel_args.h \
                shellcode_kernel/linker.ld \
                include/config.h include/linux.h \
                shellcode_kernel_1160/Makefile \
                shellcode_kernel_1160/display_ops_1160.c \
                shellcode_kernel_1160/display_ops_1160.h \
                shellcode_kernel_1160/shellcode_kernel_args_validate.h
	$(MAKE) -C shellcode_kernel_1160

# Ensure all generated headers exist before compiling the main project.
$(OBJS): | shellcode

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

source/prepare_resume.o: $(SC_K_13XX_H) $(SC_K_1160_H)
source/hv_defeat_1160.o: $(SC_BREAK_HV_H)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode_0607 clean
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_kernel_13xx clean
	$(MAKE) -C shellcode_kernel_1160 clean
	$(MAKE) -C shellcode_break_hv clean
