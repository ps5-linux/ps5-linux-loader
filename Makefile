.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-loader.elf
SRC := $(wildcard source/*.c)
OBJS := $(SRC:.c=.o)

CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel
LDFLAGS :=

SC_0607_H := shellcode_0607/shellcode_0607.h
SC_HV_H := shellcode_hv/shellcode_hv.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h
SC_HV_0250_H := shellcode_hv_0250/shellcode_hv_0250.h
SC_K_0250_H := shellcode_kernel_0250/shellcode_kernel_0250.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_HV_0250_H) \
     $(SC_K_0250_H) $(BIN)

$(SC_0607_H):
	$(MAKE) -C shellcode_0607

$(SC_HV_H):
	$(MAKE) -C shellcode_hv

$(SC_K_H): $(SC_HV_H)
	$(MAKE) -C shellcode_kernel

$(SC_HV_0250_H):
	$(MAKE) -C shellcode_hv_0250

$(SC_K_0250_H): $(SC_HV_0250_H)
	$(MAKE) -C shellcode_kernel_0250

source/prepare_0250.o: $(SC_K_0250_H)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode_0607 clean
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_hv_0250 clean
	$(MAKE) -C shellcode_kernel_0250 clean
