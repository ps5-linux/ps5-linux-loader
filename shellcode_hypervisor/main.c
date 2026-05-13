#include <stdint.h>
#include "main.h"
#include "../include/config.h"
#include "boot_linux.h"
#include "utils.h"

__attribute__((section(".entry_point"), naked)) uint32_t main(void) {

  uint32_t ebax, ebx, ecx, edx;
  uint32_t cpu_id;

  __asm__ volatile("cpuid"
                   : "=a"(ebax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(1));

  cpu_id = (ebx >> 24) & 0xFF;

  // Each CPU should have a different stack
  uintptr_t new_rsp =
      (uintptr_t)hv_base_rsp + ((uint64_t)(cpu_id)*hv_stack_size);

  __asm__ volatile("movq %0, %%rsp \n\t"
                   "movq %%rsp, %%rbp \n\t"
                   :
                   : "r"(new_rsp)
                   : "rbp", "memory");

  entry();
}