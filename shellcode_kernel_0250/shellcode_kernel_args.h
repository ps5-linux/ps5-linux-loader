// This file is shared between main payload and kernel shellcode
#ifndef SHELLCODE_KERNEL_ARGS_H
#define SHELLCODE_KERNEL_ARGS_H

#include <stdint.h>

typedef struct {
  uint16_t fw_version;
  uint64_t ktext;
  uint64_t dmap_base;
  uint64_t fun_smp_rendezvous;
  uint64_t fun_smp_no_rendevous_barrier;
  uint64_t g_vbios;
  uint64_t linux_info_va;
  uint64_t hv_entry_cave_pa;
} shellcode_kernel_args;

extern shellcode_kernel_args args; // Declared on main.c

#endif
