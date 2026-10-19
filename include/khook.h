#ifndef KHOOK_H
#define KHOOK_H

/* khook -- ported from byepervisor_reborn (see payload/khookport/README.md for provenance and
 * for the list of deliberate changes). This copy is wired to the loader's own offset table
 * (env_offset.GAD_*) instead of a self-contained fw table, so it only works on the firmware
 * offset_list provides khook's gadgets for -- currently 13.60 (off_1360).
 *
 * WHAT IT DOES
 *   Installs a #DB (vector 1) IDT gate on ONE core via TSS IST6, pivoting with
 *   `add rsp,0x28 ; ret` (env_offset.GAD_PIVOT_ADD_RSP28_RET), and arms DR0 as an EXECUTE
 *   breakpoint (DR7 = 0x403) on a target kernel function. On the hit a kernel-side ROP chain
 *   runs; kh_set_resume_rsi/rdx/rax/rdi() set the LIVE GPR values the interrupted instruction
 *   sees when execution resumes, because iretq restores no GPRs. oneshot=1 clears DR7 in the
 *   resume tail so the breakpoint cannot fire twice.
 *
 * THE ONE THING THAT MUST NOT BE "FIXED"
 *   The pivot must be a BARE `add rsp,0x28 ; ret`. 13.60's is 0x25213E and is encoded
 *   `48 83 C4 28 F3 C3` -- a `rep ret`. The F3 is ignored for RET, so it behaves as the bare
 *   pivot, and the [ist+0] chain-pointer discipline in kh_install holds. The loader's own
 *   GAD_ADD_RSP_28_POP_RBP_RET (0x9E32B4) has an extra `pop rbp` and would eat the first chain
 *   qword, shifting the whole layout by 8. They are NOT interchangeable.
 *
 * CONTRACT: kh->tss_stride must be set by the caller (0x68) before kh_install. */

#include <stdint.h>
#include <stddef.h>

typedef int (*kh_read_fn)(uint64_t kaddr, void *dst, size_t len);
typedef int (*kh_write_fn)(uint64_t kaddr, const void *src, size_t len);

typedef enum {
  KERNEL_GADGET_PIVOT_ADD_RSP28_RET,
  KERNEL_GADGET_IRETQ,
  KERNEL_GADGET_POP_RAX,
  KERNEL_GADGET_POP_RCX,
  KERNEL_GADGET_POP_RDI,
  KERNEL_GADGET_POP_RSI,
  KERNEL_GADGET_POP_RDX,
  KERNEL_GADGET_POP_R8,
  KERNEL_GADGET_POP_RSP,
  KERNEL_GADGET_STORE_RCX_R8,
  KERNEL_GADGET_STORE_RDI8_RCX,
  KERNEL_GADGET_OR_RCX_EAX,
  KERNEL_GADGET_SET_DR7,
  KERNEL_GADGET_ST_RCX_RDX,
  KERNEL_GADGET_ST_RCX_RAX,
  KERNEL_GADGET_MOV_RAX_RSI,
  KERNEL_GADGET_MOV_RAX_RDI,
  KERNEL_GADGET_REP_MOVSB,
  KERNEL_GADGET_CLD,
  KERNEL_GADGET_RET_TRAMP,
  KERNEL_GADGET_DBREG_RESUME,
  KERNEL_GADGET_STORE_RDI_RAX,
  KERNEL_GADGET_OR_RSI_ECX,
  KERNEL_GADGET_MAX
} kgadget_t;

uint64_t kgadget(kgadget_t gadget);   /* ktext + env_offset.GAD_*, or 0 if unavailable */

#define KH_RC_RBP  0x20
#define KH_RC_RSP  0x28
#define KH_RC_RIP  0x38
#define KH_RC_DR7  0xa0

#define KH_USER_CS        0x43
#define KH_USER_SS        0x3b
#define KH_RFLAGS_USER    0x202ULL
#define KH_RF             0x10000ULL
#define KH_DR7_BP0_EXEC   0x403ULL

#define KH_GATE_INTERRUPT 0xE
#define KH_VEC_DB         1
#define KH_TSS_IST1       0x24
#define KH_TSS_IST(k)     (KH_TSS_IST1 + ((uint64_t)((k)-1) * 8))
#define KH_TSS_STRIDE     0x68
#define KH_KIMG_MAX       0x4000000ULL

#define KH_OFF_CHAIN_ARM   0x040
#define KH_OFF_CHAIN_CONT  0x0a0
#define KH_OFF_RESUME      0x140
#define KH_OFF_CHAIN_DISP  0x240
#define KH_OFF_USER        0x440
#define KH_SCRATCH_MIN     0x500
#define KH_SCRATCH_BIG     0x4000
#define KH_OFF_BIG_CHAIN   0x3a00

typedef struct {
  uint8_t *buf;
  size_t   cap;
  size_t   len;
  int      err;
} kh_chain_t;

void kh_chain_init(kh_chain_t *chain, uint8_t *buf, size_t cap);
int  kh_chain_q(kh_chain_t *chain, uint64_t raw);
int  kh_chain_g(kh_chain_t *chain, kgadget_t gadget);
int  kh_chain_store(kh_chain_t *chain, uint64_t kaddr, uint64_t val);
int  kh_chain_memcpy(kh_chain_t *chain, uint64_t dst_kaddr, uint64_t src_kaddr, uint64_t n_bytes);
int  kh_chain_call(kh_chain_t *chain, uint64_t fn_kaddr, int argc,
                   uint64_t a0, uint64_t a1, uint64_t a2);

typedef struct {
  kh_read_fn  read;
  kh_write_fn write;

  uint64_t kernel_base;
  uint64_t idt_base;
  uint64_t tss_base;
  uint64_t tss_stride;
  int      core_id;
  uint64_t scratch_base;
  int      ist_index;
  uint64_t hook_kaddr;

  uint16_t kcs;
  uint64_t saved_gate_lo, saved_gate_hi, saved_ist;
  int      installed;

  /* 1 = fire once - the resume tail clears DR7 before returning
   * 0 = persistent */
  int      oneshot;

  uint64_t resume_rip;

  int resume_rax_set;
  uint64_t resume_rax;
  int resume_rsi_set;
  uint64_t resume_rsi;
  int resume_rdi_set;
  uint64_t resume_rdi;
  int resume_rdx_set;
  uint64_t resume_rdx;

  uint64_t arm_rip_slot;
  uint64_t arm_rsp_slot;
} khook_t;

int  kh_init(khook_t *kh, kh_read_fn rd, kh_write_fn wr, uint64_t kernel_base, uint64_t scratch_base, int ist_index);

void kh_set_hook_target(khook_t *kh, uint64_t kaddr);
void kh_set_resume_rip(khook_t *kh, uint64_t kaddr);
void kh_set_resume_skip(khook_t *kh, uint64_t skip);

void kh_set_resume_rax(khook_t *kh, uint64_t rax);
void kh_clear_resume_rax(khook_t *kh);
void kh_set_resume_rsi(khook_t *kh, uint64_t rsi);
void kh_clear_resume_rsi(khook_t *kh);
void kh_set_resume_rdi(khook_t *kh, uint64_t rdi);
void kh_clear_resume_rdi(khook_t *kh);
void kh_set_resume_rdx(khook_t *kh, uint64_t rdx);
void kh_clear_resume_rdx(khook_t *kh);

void kh_set_tables(khook_t *kh, uint64_t idt_base, uint64_t tss_base);
void kh_set_core(khook_t *kh, int core_id);

uint64_t kh_user_data_addr(const khook_t *kh);

int  kh_install(khook_t *kh, const kh_chain_t *handler);
void kh_trigger(khook_t *kh);

int  kh_disarm(khook_t *kh);
int  kh_restore(khook_t *kh);

#endif /* KHOOK_H */
