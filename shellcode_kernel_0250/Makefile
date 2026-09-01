ifeq ($(shell uname -m),aarch64)
CC      = x86_64-linux-gnu-gcc
LD      = x86_64-linux-gnu-ld
OBJCOPY = x86_64-linux-gnu-objcopy
else ifeq ($(shell uname -m),arm64)
CC      = x86_64-elf-gcc
LD      = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
else
CC      = gcc
LD      = ld
OBJCOPY = objcopy
endif
CFLAGS  = -Os -fomit-frame-pointer -fno-stack-protector -ffreestanding -nostdlib -fcf-protection=none -mgeneral-regs-only -mno-red-zone -m64 -fPIE -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections -MMD -MP
LDFLAGS = -pie -T linker.ld -Wl,--no-warn-rwx-segments,--gc-sections
TARGET  = shellcode_kernel_0250.elf
TEXT_BIN = shellcode_kernel_0250.bin
dump = shellcode_kernel_0250.h

SRC = main.c boot_linux.c utils.c
OBJ = $(SRC:.c=.o)

all: $(dump)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $(TARGET) $(TEXT_BIN)

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) $(TARGET) $(TEXT_BIN) $(dump)

$(dump): $(TEXT_BIN)
	xxd -i $(TEXT_BIN) > $(dump)

-include $(OBJ:.o=.d)
