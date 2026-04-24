#include "main.h"
#include "../shellcode_kernel/shellcode_kernel.h"
#include "hv_defeat.h"
#include "loader.h"
#include "offsets.h"
#include "utils.h"
#include <stdio.h>
#include <unistd.h>

int main(void) {

  if (setup_env()) {
    printf("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }
  if (hv_defeat()) {
    printf("Something went wrong while defeating Hypervisor.\nPlease make sure "
           "your fw is supported.");
    return -1;
  }

  if (fetch_linux(&linux_i)) {
    printf("Something went wrong while installing linux files.\n");
    return -1;
  }

  if (prepare_resume()) {
    printf("Something went wrong while preparing resume.\n");
    return -1;
  }

  printf("Everything done. Go to rest mode, wait for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  while (1) {
    sleep(30);
  }

  return 0;
}

int setup_env(void) {
  printf("Welcome to ps5-linux-loader. We'll defeat HV and prepare the system "
         "to boot Linux on sleep resume.\n");
  if (set_offsets())
    return -1;
  if (init_global_vars())
    return -1;
  return 0;
}

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
  uint64_t dest_data =
      ktext + env_offset.KERNEL_DATA_CAVE; // For arguments only, rest of .data
                                           // variables are in shellcode

  uint64_t sz = shellcode_kernel_text_len;

  uint32_t CHUNK = 0x1000;
  uint64_t written = 0;
  while (written < sz) {
    uint32_t n = (sz - written > CHUNK) ? CHUNK : (uint32_t)(sz - written);
    kernel_copyin(&shellcode_kernel_text[written], dest_text + written, n);
    written += n;
  }
  DEBUG_PRINT("  copied %d bytes to text cave\n", sz);

  DEBUG_PRINT("\n\nI wrote this shellcode text on %016lx (ktext+%08lx):\n",
              dest_text, env_offset.KERNEL_CODE_CAVE);
  for (uint64_t i = 0; i < sz; i++) {
    DEBUG_PRINT("%02x", kread8(dest_text + i));
  }
  DEBUG_PRINT("\n\n");

  shellcode_kernel_args args;

  // Fill structure of ShellCode Arguments
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

  args.linux_info_va = linux_i.linux_info; // To relocate by kernel shellcode
  // bzimage_va and initrd_va are passed in the linux_info structure

  // Copy arguments to small .data cave
  kernel_copyin(&args, dest_data, sizeof(args));

  DEBUG_PRINT("\n\nI wrote this arguments data on %016lx (ktext+%08lx):\n",
              dest_data, env_offset.KERNEL_DATA_CAVE);
  for (uint64_t i = 0; i < sz; i++) {
    DEBUG_PRINT("%02x", kread8(dest_data + i));
  }
  DEBUG_PRINT("\n\n");

  // Now find the address 0x11AA11AA11AA11AA used as marker for args_ptr and
  // overwrite it with proper VA in .data for arguments
  int offset = -1;
  for (int i = 0; i < 0x40; i++) {
    if (*(uint64_t *)((uint64_t)shellcode_kernel_text + i) ==
        0x11AA11AA11AA11AA) {
      offset = i;
      break;
    }
  }
  if (offset == -1) {
    printf("Could not find offset of args_ptr address - Aborting\n");
  }
  kwrite64(dest_text + offset, dest_data);

  DEBUG_PRINT("\n\nI wrote this ptr %016lx on %016lx (offset %08lx)\n",
              dest_data, dest_text + offset, offset);

  uint64_t instr_to_patch =
      ktext + env_offset.HOOK_ACPI_WAKEUP_MACHDEP; // AcpiSetFirmwareWakingVector
                                                   // in acpi_wakeup_machdep
  int64_t diff_call = dest_text - instr_to_patch;
  uint8_t new_instr[5];
  new_instr[0] = 0xE8; // Call Near
  *((uint32_t *)&new_instr[1]) =
      (int32_t)(diff_call - 5); // Call Offset is relative to the next
                                // instruction and Call uses 5 bytes

  // Patch instruction
  kernel_copyin(new_instr, instr_to_patch, 5);
  DEBUG_PRINT("Instruction patched\n");

  // Patch debug exception
  kwrite8(ktext + env_offset.KERNEL_DEBUG_PATCH, 0xC3);
  // Patch cfi_check
  kwrite8(ktext + env_offset.KERNEL_CFI_CHECK, 0xC3);

  return 0;
}