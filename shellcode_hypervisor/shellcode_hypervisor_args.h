#include <stdint.h>

typedef struct {
  uint64_t bzimage_pa;
  uint64_t initrd_pa;
  uint64_t linux_info_pa;
} shellcode_hypervisor_args;