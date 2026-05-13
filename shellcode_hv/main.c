#include "../include/config.h"
#include "boot_linux.h"
#include "utils.h"
#include <stdint.h>

__attribute__((section(".entry_point"), naked)) uint32_t main(void) {
  // We enter this function after CR3 was updated to 1:1 mapping
  // We need to point RSP/RBP to a good known valid address
  uint32_t ebax, ebx, ecx, edx;
  uint32_t cpu_id;

  __asm__ volatile("cpuid"
                   : "=a"(ebax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(1));

  cpu_id = (ebx >> 24) & 0xFF;

  // We point to a location after the main linux boot code
  // Each CPU should have a different location
  uintptr_t new_rsp =
      (uintptr_t)hv_base_rsp + ((uint64_t)(cpu_id)*hv_stack_size);

  // WARNING: This invalidates current local variables
  __asm__ volatile("movq %0, %%rsp \n\t"
                   "movq %%rsp, %%rbp \n\t"
                   :
                   : "r"(new_rsp)
                   : "rbp", "memory");

  entry();
}
