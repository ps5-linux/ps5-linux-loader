// This file is shared between kernel shellcode and hypervisor shellcode

#include <stdint.h>

typedef struct {
  uint64_t bzimage_pa;    // Already relocated by Kernel shellcode
  uint64_t initrd_pa;     // Already relocated by Kernel shellcode
  uint64_t linux_info_pa; // Already relocated by Kernel shellcode
} shellcode_hypervisor_args;