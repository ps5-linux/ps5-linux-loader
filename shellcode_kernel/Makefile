ifeq ($(shell uname -m),aarch64)
CC      = x86_64-linux-gnu-gcc
LD      = x86_64-linux-gnu-ld
OBJCOPY = x86_64-linux-gnu-objcopy
else
CC      = gcc
LD      = ld
OBJCOPY = objcopy
endif
# EXTRA_CFLAGS carries per-build defines, e.g. the op-count bisect lever:
#   make -C shellcode_kernel EXTRA_CFLAGS=-DPS5_OP_LIMIT=16
CFLAGS  = -O2 -fno-stack-protector -ffreestanding -nostdlib -fcf-protection=none -mno-sse -mno-sse2 -m64 $(EXTRA_CFLAGS)
LDFLAGS = -T linker.ld
TARGET  = shellcode_kernel.elf
TEXT_BIN = shellcode_kernel.bin
dump = shellcode_kernel.h

SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

all: $(dump)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $(TARGET) $(TEXT_BIN)

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(dump)

$(dump): $(TEXT_BIN)
	xxd -i $(TEXT_BIN) > $(dump)
