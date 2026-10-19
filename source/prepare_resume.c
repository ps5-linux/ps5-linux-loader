#include "prepare_resume.h"
#include "../shellcode_kernel/shellcode_kernel.h"
#include "../shellcode_kernel/shellcode_kernel_args.h"
#include "config.h"
#include "iommu.h"
#include "offsets.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

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

  // Copy shellcode_kernel.
  *shellcode_kernel =
      mmap(NULL, ALIGN_UP(shellcode_kernel_bin_len, PAGE_SIZE),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  *shellcode_kernel_len = shellcode_kernel_bin_len;
  memcpy(*shellcode_kernel, shellcode_kernel_bin, shellcode_kernel_bin_len);

  uint64_t args_va = prepare_sck_args();
  if (update_sck_args_ptr((uint64_t)*shellcode_kernel, args_va))
    return -1;

  // Install shellcode_kernel in kernel space.
  for (int i = 0; i < shellcode_kernel_bin_len; i += PAGE_SIZE) {
    install_page_syscore(kernel_cave_shellcode + i,
                         vtophys_user((uintptr_t)*shellcode_kernel + i), 0);
  }

  if (remove_xotext()) {
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
  args.fw_version = fw;
  args.ktext = ktext;
  args.kdata = kdata;
  args.dmap_base = dmap;

  args.fun_printf = ktext + env_offset.FUN_PRINTF;
  args.fun_hv_iommu_set_buffers = ktext + env_offset.FUN_HV_IOMMU_SET_BUFFERS;
  args.fun_hv_iommu_wait_completion =
      ktext + env_offset.FUN_HV_IOMM_WAIT_COMPLETION;
  args.fun_smp_rendezvous = ktext + env_offset.FUN_SMP_RENDEZVOUS;
  args.fun_smp_no_rendevous_barrier =
      ktext + env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER;
  args.g_vbios = ktext + env_offset.G_VBIOS;

  /* A MISSING offset must stay NULL, not become ktext+0.
   * off_0800/off_0900 shipped without these three, so each resolved to ktext itself
   * and boot_linux.c called straight into the kernel ELF header. Pass 0 instead and
   * let the call sites skip -- a reported skip beats executing a header. */
#define VFN(f) (env_offset.f ? (ktext + env_offset.f) : 0)
  args.fun_transmitter_control = VFN(FUN_TRANSMITTER_CONTROL);
  args.fun_mp3_initialize = VFN(FUN_MP3_INITIALIZE);
  args.fun_mp3_invoke = VFN(FUN_MP3_INVOKE);
#undef VFN

  args.iommu_softc = ktext + env_offset.IOMMU_SOFTC;

  args.kernel_uart_override = ktext + env_offset.KERNEL_UART_OVERRIDE;
  args.kernel_cfi_check = ktext + env_offset.KERNEL_CFI_CHECK;

  /* HV_HANDLE_VMEXIT_PA / HV_CODE_CAVE_PA in the offset table are ABSOLUTE physical addresses,
   * derived assuming the HV carveout sits at HV_BASE_REGULAR (0x62800000, true on devkit/base
   * SKU). On PS5 Pro retail the carveout REGION is elsewhere (~0x8e0000000, confirmed
   * 2026-10-18 on real hardware), AND the HV's own CODE starts a further 8MB into that region
   * (HV_CODE_OFFSET_PRO) -- confirmed against the independent public fix in
   * github.com/ps5-linux/ps5-linux-loader PR #47, tested working on real retail Pro hardware.
   * Using the table values unmodified writes/patches into unrelated physical memory instead of
   * the real hypervisor, which is what crashed the console on wake before this fix. Re-base
   * both fields onto the ACTUAL HV code location for THIS console. A failed derivation (0)
   * falls back to the raw table values -- same as before this fix existed, so firmware ranges
   * that never had this carveout concept at all are unaffected. */
  uint64_t hv_base_now = derive_hv_base();
  if (hv_base_now) {
    uint64_t hv_code_base = hv_base_now;
    if (fw == 0x1360 && sceKernelGetMainSocId() == SOC_ID_PS5_PRO)
      hv_code_base += HV_CODE_OFFSET_PRO;
    args.hv_handle_vmexit_pa = hv_code_base + (env_offset.HV_HANDLE_VMEXIT_PA - HV_BASE_REGULAR);
    args.hv_code_cave_pa = hv_code_base + (env_offset.HV_CODE_CAVE_PA - HV_BASE_REGULAR);
  } else {
    args.hv_handle_vmexit_pa = env_offset.HV_HANDLE_VMEXIT_PA;
    args.hv_code_cave_pa = env_offset.HV_CODE_CAVE_PA;
  }
  notify("PREP: hv_base=0x%lx hv_handle_vmexit_pa=0x%lx hv_code_cave_pa=0x%lx\n",
         (unsigned long)hv_base_now, (unsigned long)args.hv_handle_vmexit_pa,
         (unsigned long)args.hv_code_cave_pa);

  args.linux_info_va = linux_i.linux_info;

  uint64_t args_cave = pa_to_dmap(alloc_page());
  kernel_copyin(&args, args_cave, sizeof(args));

  return args_cave;
}
