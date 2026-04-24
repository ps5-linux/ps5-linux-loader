ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif


CC      = gcc
LD      = ld
CFLAGS  = -O2 -fno-stack-protector -ffreestanding -nostdlib -I$(PS5_PAYLOAD_SDK)/target/include
LDFLAGS = -T linker.ld
TARGET  = shellcode_kernel.elf
TEXT_BIN = shellcode_text.bin

SRC = main.c utils.c kernel_code.c
OBJ = $(SRC:.c=.o)

dump = shellcode_kernel.h

all: $(dump)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEXT_BIN): $(TARGET)
	objcopy -O binary -j .text $(TARGET) $(TEXT_BIN)

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(dump)

$(dump): $(TEXT_BIN)
	python3 bin_to_c_kernel.py $(TEXT_BIN)