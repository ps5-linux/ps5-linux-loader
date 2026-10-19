CC      ?= gcc
CFLAGS  := -O2 -ffreestanding -nostdlib -fno-pic -fno-plt \
           -fno-stack-protector -fno-stack-clash-protection \
           -fomit-frame-pointer -fno-asynchronous-unwind-tables \
           -fcf-protection=none -fno-jump-tables -mgeneral-regs-only \
           -mno-red-zone -Wall -Wextra

all: shellcode_ap.h

entry.o: entry.S
	$(CC) -c entry.S -o entry.o

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

shellcode_ap.elf: entry.o main.o linker.ld
	ld -nostdlib -no-pie -T linker.ld entry.o main.o -o shellcode_ap.elf

shellcode_ap.bin: shellcode_ap.elf
	objcopy -O binary shellcode_ap.elf shellcode_ap.bin
	@SIZE=$$(stat -c %s shellcode_ap.bin); \
	 if [ $$SIZE -ge 3840 ]; then \
	   echo "FATAL: AP blob is $$SIZE bytes, must be < 3840 (0xF00) to leave room for params" >&2; \
	   exit 1; \
	 fi; \
	 echo "shellcode_ap: $$SIZE bytes"

shellcode_ap.h: shellcode_ap.bin
	xxd -i -n shellcode_ap_bin shellcode_ap.bin > shellcode_ap.h

clean:
	rm -f *.o *.elf *.bin shellcode_ap.h

.PHONY: all clean
