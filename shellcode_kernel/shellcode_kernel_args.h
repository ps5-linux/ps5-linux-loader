// This file is shared between main payload and kernel shellcode
#ifndef SHELLCODE_KERNEL_ARGS_H
#define SHELLCODE_KERNEL_ARGS_H

#include <stdint.h>

typedef struct {
  uint16_t fw_version;
  uint64_t ktext;
  uint64_t kdata;
  uint64_t dmap_base;
  uint64_t fun_printf;
  uint64_t fun_vtophys;
  uint64_t fun_hv_iommu_set_buffers;
  uint64_t fun_hv_iommu_wait_completion;
  uint64_t fun_acpi_set_fw_waking_vector;
  uint64_t fun_smp_rendezvous;
  uint64_t fun_smp_no_rendevous_barrier;
  uint64_t fun_transmitter_control;
  uint64_t fun_mp3_initialize;
  uint64_t fun_mp3_invoke;
  uint64_t g_vbios;
  uint64_t iommu_mmio_va;
  uint64_t iommu_cb2_va;
  uint64_t iommu_cb3_va;
  uint64_t iommu_eb_va;
  uint64_t vmcb[16];
  uint64_t kernel_uart_override;
  uint64_t hv_handle_vmexit_pa;
  uint64_t hv_code_cave_pa;
  uint64_t linux_info_va; // To relocate by kernel shellcode
} shellcode_kernel_args;

extern shellcode_kernel_args args; // Declared on main.c

#endif
