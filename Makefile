.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-loader.elf
SRC := $(wildcard source/*.c)
OBJS := $(SRC:.c=.o)

# Agregamos los headers de los shellcodes a los CFLAGS para que los encuentre en source/main.c
CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hypervisor -Ishellcode_kernel
LDFLAGS :=

# Rutas de los headers generados
SC_HV_H := shellcode_hypervisor/shellcode_hypervisor.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h

# 1. Regla principal: Construir los shellcodes antes que los objetos del main
all: $(SC_HV_H) $(SC_K_H) $(BIN)

# 2. Reglas para disparar el Make en las subcarpetas
# Usamos .PHONY de forma indirecta o forzamos la entrada a la carpeta
$(SC_HV_H):
	$(MAKE) -C shellcode_hypervisor

$(SC_K_H):
	$(MAKE) -C shellcode_kernel

# 3. Los objetos dependen de que los headers de los shellcodes existan
# Si main.c hace #include "shellcode_hypervisor.h", necesita estos targets
$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# 4. Link final
$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode_hypervisor clean
	$(MAKE) -C shellcode_kernel clean
