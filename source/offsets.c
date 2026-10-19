#include "offsets.h"

#define KERNEL_TEXT 0xFFFFFFFF80210000























/*
 * FW 7.61, THE khook (13xx) ROUTE -- not the hv_defeat_0607 route off_0761 serves.
 *
 * WHY THIS EXISTS: 4.51 and 7.61 have only ever booted Linux via hv_defeat_0304/0506/0607.
 * The 13xx exploit has NEVER run on either, so "7.61 works" says nothing about it, and
 * firmware version was confounded with loader route in every comparison made so far
 * (CONTEXT: "CONFOUND: FIRMWARE VERSION AND LOADER ROUTE ARE NOT INDEPENDENT"). 7.61 has a
 * picture today via 0607, so running the khook route on the SAME firmware isolates the
 * route as the variable. off_0761 is left untouched so both can be built and compared.
 *
 * GAD_STORE_RCX_R8_RET IS DELIBERATELY ABSENT (zero). That is the signal kh_retargeted()
 * tests: 7.61 contains none of 13.60's mov [rcx],rax / [rcx],rdx / [rcx],r8 / [rdi+8],rcx /
 * pop r8 / mov dr7,rax / or [rcx],eax at a drop-in ret, and 13.60 contains neither of the
 * two gadgets below. The inventories are disjoint, so khook emits whichever it is given.
 *
 * Every value below was read out of 7.61's own .text and the bytes printed and checked;
 * the two KERNEL_SYM_* derivations were validated by reproducing off_1360's recorded
 * values on 13.60 first.
 */

/*
 * FW 12.00.00 -- ported 2026-09-14.
 *
 * Provenance for every entry is recorded in findings/PORT-1200-COMPLETE.md.
 * Values were re-derived from k12.elf rather than extrapolated from 7.61.
 *
 * NOTE: this firmware does NOT use hv_defeat_0607. The MSR 0x1B (APIC_BASE)
 * intercept handler was removed between 11.00 and 12.00, so the wrmsr at the
 * heart of that technique is logged and discarded -- see
 * findings/BLOCKER-apic-base-patched-1200.md. The defeat for 12.00 is the
 * S3/AP root-0 route (findings/PORT-S3-AP-ROOT0-1200.md). The gadget and
 * kernel offsets below are still required by prepare_resume.c and gpu.c.
 */




/*
 * FW 8.00 and 9.00 -- derived 2026-10-15 for the FIRMWARE WALK, hv_defeat_0607 route.
 *
 * This route needs only ACPIGBL_FACS, COMMON_TSS, FUN_MEMCPY, five pop gadgets, WRMSR, IDT
 * and KERNEL_CODE_CAVE, so the khook gadget shortfall on 8.00/9.00 is irrelevant here.
 *
 * NOT YET BOOTED. The open question the walk exists to answer is whether the APIC_BASE MSR
 * intercept hv_defeat_0607 exploits still exists at 8.00/9.00/10.00 -- it is gone by 12.00,
 * and 11.00 panicked when it tried, so somewhere in this range it dies.
 */

/*
 * FW 9.00 -- derived 2026-10-15 by signature. NOT BOOTED. 36 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 10.00 -- derived 2026-10-15 for the FIRMWARE WALK, via the hv_defeat_0607 route.
 *
 * Derivation methods, each validated by reproducing recorded values on existing tables
 * before being applied here:
 *   ACPIGBL_FACS      AcpiSetFirmwareWakingVector's opening `mov rax,[rip+FACS]` + the stock
 *                     ACPICA tail. Reproduces off_1200 and off_1360.
 *   COMMON_TSS        init_secondary's prologue then its SECOND lea (4c 8d 05 at +0x18).
 *                     Reproduces off_1200 and off_1360.
 *   IDT               COMMON_TSS - 0x2CE0. That delta holds on 7.61, 12.00, 13.00 AND 13.60 --
 *                     four independent confirmations, one of them upstream Reborn's own
 *                     13_00.h. Still an inference; suspect it first if 10.00 misbehaves.
 *   KERNEL_UART_OVERRIDE  get_override accessor, disambiguated by caller count == 3.
 *   G_VBIOS           the `41 54 53 50 ... lea rcx,[rip+G_VBIOS]` site. Reproduces off_0761,
 *                     off_1200 and off_1360.
 *   KERNEL_CODE_CAVE  longest NOP run + 1. Independently reproduced off_1200's 0xD40500.
 *   FUN_SMP_NO_RENDEVOUS_BARRIER  the e9-thunk to the 6-byte empty stub 0x240 below
 *                     FUN_SMP_RENDEZVOUS. Reproduces off_1200's 0x31DB30 and off_1360's
 *                     0x261E08.
 *   GAD_RET_TRAMP     POP_RAX+1. The sweep's first-match value (0x92) is header data and is
 *                     NOT used. Upstream Reborn annotates the same rule in 13_00.h.
 *
 * The khook fields are included too (10.00 has SET_DR7 and lacks only GAD_OR_RCX_EAX_RET,
 * which is emitted only when oneshot=0), so this table can also drive hv_defeat_13xx if the
 * walk ever wants that comparison on 10.00.
 */

/*
 * FW 11.00 -- derived 2026-10-15 for the ROUTE A/B.
 *
 * WHY THIS FIRMWARE: it is the only one that runs BOTH hv routes unmodified.
 * hv_defeat_0607 needs the MSR 0x1B (APIC_BASE) intercept handler, which was removed
 * between 11.00 and 12.00, so 11.00 still has it. hv_defeat_13xx needs GAD_SET_DR7_RAX
 * (present here) and uses GAD_OR_RCX_EAX_RET ONLY in the oneshot=0 branch -- with
 * oneshot=1 it is never emitted, which is why that field being 0 below is fine.
 *
 * Every value was derived by a method that first reproduced the recorded value on at least
 * two tables we already trust. The three that A3 needed IDA for on 12.00 were found here by
 * their referencing code instead:
 *   ACPIGBL_FACS         AcpiSetFirmwareWakingVector opens `mov rax,[rip+FACS]` then the
 *                        stock ACPICA body -- one hit per kernel, reproduces off_1200 and
 *                        off_1360.
 *   COMMON_TSS           init_secondary's prologue, then its SECOND lea (4c 8d 05, +0x18).
 *   KERNEL_UART_OVERRIDE get_override is `push rbp; mov rbp,rsp; movzx eax,[rip+d];
 *                        pop rbp; ret`. That shape alone gives 28 candidates, so the
 *                        disambiguator is CALLER COUNT == 3, unique on both knowns.
 *   G_VBIOS              the `41 54 53 50 48 89 fb 48 85 ff 74 1c ; lea rcx,[rip+G_VBIOS]`
 *                        site -- reproduces off_0761, off_1200 AND off_1360.
 *
 * *** IDT IS INFERRED, NOT MEASURED. *** COMMON_TSS - IDT is 0x2CE0 on both 12.00 and
 * 13.60, so IDT is taken as COMMON_TSS - 0x2CE0. Corroboration: that address has exactly 2
 * rip-relative referencing sites, the same count as the known-good IDTs on both. Suspect
 * this first if an 11.00 build misbehaves.
 *
 * PS5_WIFI_FW_OFFSET/SIZE are left 0: firmware.c checks for 0 and returns -1 with a notify,
 * so WiFi simply does not load. It is not on the boot path.
 */


/*
 * FW 13.00 -- assembled 2026-10-15.
 *
 * The khook half (KERNEL_SYM_*, IDT, COMMON_TSS and the gadget set) is taken VERBATIM from
 * upstream byepervisor_reborn include/offsets/13_00.h, so those values are upstream's own
 * and are proven on hardware there. The data-side fields were derived here with methods
 * each validated by reproducing the recorded values on off_1200 and off_1360 first.
 *
 * PURPOSE: 13.60 boots Linux on this route and shows NO PICTURE. Is that specific to 13.60
 * or true of every 13.x? One flash answers it, with the route held constant -- which is
 * exactly what the 11.00 A/B could not manage.
 */

/* =====================================================================================
 * 13.60 -- the khook route (hv_defeat_13xx.c)
 *
 * Route: hook the kernel's OWN AP-start call (khv_startup_mp) with a DR0 execute
 * breakpoint, rewrite its RSI/RDX, and let the AP payload clear NESTED_CTRL.NP_ENABLE on
 * all 16 VMCBs. That sidesteps the DISABLE_STARTUP_MP ordering trap that blocked the
 * "issue HCALL 0x0f ourselves from the FACS #GP" design (RESOLVED-v7-startup-mp-window.md).
 *
 * Every value marked [V] is byte-verified against k1360_verify.i64 by
 * HVXring0/ida/verify_reborn_k1360.py -> SAFE TO SEND, and re-confirmed against
 * HVXring0/findings/LINUX-OFFSETS-13.60.md and PATCH-INVENTORY-13.60.md.
 *
 * All of these are now derived and verified. Two sources, both offline:
 *   findings/LINUX-OFFSETS-13.60-DERIVED.md  (kernel side, from k1360_verify.i64 / k761.i64)
 *   findings/HV-SIDE-13.60-DERIVED.md        (HV side + the e820 provenance)
 *
 * Standalone verifiers under HVXring0/ida/ end in SAFE TO SEND:
 *   verify_reborn_k1360.py, verify_cfi_cave1360.py, verify_smp1360.py, verify_bootoffs1360.py
 *
 * hv_defeat_13xx() still aborts if any field IT depends on is 0 -- a wrong offset in a ROP
 * chain is arbitrary code execution on a live kernel, so a loud refusal beats a plausible
 * guess. The fields deliberately left 0 (STOPPED_CPUS, FUN_STOP_CPUS, FUN_AS_LAPIC_EOI,
 * FUN_HV_UNMAP_PT_TMR, HOOK_ACPI_WAKEUP_MACHDEP) are the 0506-only ones, unused on this
 * route, and are not in that check.
 * ===================================================================================== */
offset_list off_1360 = {
    /* ---- loader plumbing ---- */
    /* IOMMU_SOFTC confirmed by the resume path dereferencing it at +0x78/+0x80/+0x60b90,
     * exactly iommu.h's IOMMU_SC_CB2_PTR / CB3_PTR / EB_PTR. */
    .IOMMU_SOFTC        = 0x3543A70,
    /* Same field value as 12.00; the gbase_suspend_game_vm shape (bound 16, 0x100 gvmspace
     * stride) is unchanged. */
    .VMSPACE_VM_VMID    = 0x1EC,
    .VMSPACE_VM_PMAP    = 0x1D8,      /* used successfully by every payload */
    /* Cross-validated: 12.00's and 13.60's gvmspace arrays are each reached by exactly 36
     * rip-relative refs with identical deltas. */
    .DATA_BASE_GVMSPACE = 0x3BAA570,

    /* ---- guest prep ---- */
    .ACPIGBL_FACS       = 0x39C9490,  /* [V] LINUX-OFFSETS-13.60.md ADDENDUM 2 */
    .IDT                = 0x3BB4300,  /* [V] */
    .COMMON_TSS         = 0x3BB6FE0,  /* [V] stride 0x68 */
    .FUN_MEMCPY         = 0x2590B0,   /* [V] */

    /* 0506-only fields; unused on 13.60 (no #IPI/#GP stop-cpus dance on this route) */
    .STOPPED_CPUS       = 0,
    .FUN_STOP_CPUS      = 0,
    .FUN_AS_LAPIC_EOI   = 0,
    .FUN_HV_UNMAP_PT_TMR = 0,
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x3912CB,  /* [V] derived via "Warning: suspend tsc is wrong" string xref -> resume tail `xor edi,edi;xor esi,esi; call AcpiSetFirmwareWakingVector(0x6D37A0)`. Method reproduces 3.00=0x390E73 & 4.51=0x3A75E3 EXACTLY. (prior 0x66BBA2 was a shape-only lookalike, WRONG.) */

    /* ---- shared gadgets ---- */
    .GAD_ADD_RSP_28_POP_RBP_RET = 0x9E32B4,  /* [V] add rsp,0x28 ; pop rbp ; ret */
    .GAD_IRETQ            = 0x257B3D,  /* [V] */
    .GAD_POP_RAX_RET      = 0xB8CA6E,  /* [V] pop rax ; ret  (0xB8CA6D is pop r8) */
    .GAD_POP_RDI_RET      = 0x28CE6D,  /* [V] */
    .GAD_POP_RSI_RET      = 0x34CB91,  /* [V] */
    .GAD_POP_RDX_RET      = 0x2A0F7B,  /* [V] */
    .GAD_POP_RCX_RET      = 0x2918B2,  /* [V] */
    .GAD_POP_RSP_RET      = 0xB8291B,  /* [V] */
    .GAD_WRMSR_RET        = 0x255034,  /* [V] unique in the image */
    .GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET = 0x3D3F2A,  /* [V] */

    /* ---- khook scratch + the AP handoff ---- */
    .KERNEL_SYM_HV_MP_STARTUP_CALL     = 0xC16EE0,   /* [V] the hook target */
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x269FB8,   /* [V] where the AP returns to bringup */
    .KERNEL_SYM_DATA_CAVE              = 0x2D39000,  /* [V] khook scratch + oracle */

    /* ---- khook's own gadget set (semantics are load-bearing) ---- */
    .GAD_PIVOT_ADD_RSP28_RET  = 0x25213E,  /* [V] 48 83 C4 28 F3 C3  add rsp,0x28 ; rep ret.
                                            * The F3 is ignored for RET, so this IS the bare
                                            * pivot khook assumes and the [ist+0] chain
                                            * discipline holds. Do NOT swap in 0x9E32B4 --
                                            * its extra pop rbp shifts the layout by 8. */
    .GAD_POP_R8_RET           = 0xB8CA6D,  /* [V] 47 58 C3 (REX 0x47, not 0x41) */
    .GAD_STORE_RCX_R8_RET     = 0x474389,  /* [V] 4C 89 01 C3  mov [rcx],r8 ; ret */
    .GAD_STORE_RDI8_RCX_RET   = 0x32693F,  /* [V] 48 89 4F 08 C3  mov [rdi+8],rcx ; ret */
    .GAD_OR_RCX_EAX_RET       = 0x321EA0,  /* [V] 09 01 C3  or [rcx],eax ; ret */
    .GAD_SET_DR7_RAX          = 0xA07BA6,  /* [V] 0F 23 F8 44 89 C0 C3 */
    .GAD_ST_RCX_RDX_RET       = 0x82B915,  /* [V] 48 89 11 C3 -- our earlier scan wrongly
                                            * reported NO such gadget; it exists. */
    .GAD_ST_RCX_RAX_RET       = 0x2BB28F,  /* [V] 48 89 01 31 C0 C3 */
    .GAD_MOV_RAX_RSI_RET      = 0x8E3A44,  /* [V] 48 89 F0 C3 */
    .GAD_MOV_RAX_RDI_RET      = 0xBECDEA,  /* [V] 48 89 F8 C3 */
    .GAD_REP_MOVSB            = 0x25D027,  /* [V] F3 A4 66 90 F3 C3 */
    .GAD_CLD_RET              = 0x30644F,  /* [V] FC C3 */
    .GAD_RET_TRAMP            = 0x2912A2,  /* [V] C3 */
    .GAD_DBREG_RESUME         = 0x2529D8,  /* [V] resumectx tail. Unnamed raw offset: it
                                            * bakes in rbp 0x20 / rsp 0x28 / rip 0x38 /
                                            * dr7 0xa0 and loads DR0 from RAX. Verified
                                            * against the disassembly in
                                            * VERIFY-reborn-offsets-13.60.md. */

    /* ---- shellcode_kernel / shellcode_hv plumbing ---- */
    /* 0x6D40 bytes of 0x90 at the tail of the R-X segment, zero xrefs, no function overlap.
     * Upstream's 0x500 is 0xCC blanked code on this firmware, exactly as it was on 12.00. */
    .KERNEL_CODE_CAVE          = 0xCB92C0,
    /* The THUNK, not the printf body -- CFI admits only thunks. 16873 xrefs; the body it
     * jumps to is 0x4ADD60, which the third-party Reborn table calls "printf". They are NOT
     * different functions: 0x25D410 is `jmp <body>`. Same pattern as off_1200. */
    .FUN_PRINTF                = 0x25D410,
    .FUN_HV_IOMMU_SET_BUFFERS  = 0xC16B00,  /* VMMCALL wrapper, mov eax,6 */
    .FUN_HV_IOMM_WAIT_COMPLETION = 0xC16A40,/* VMMCALL wrapper, mov eax,0Ah */
    /* CORRECTED: the earlier recorded candidate 0xC9FA20 is a lock wrapper
     * (`mov rdi,[rdi+8] ; add rdi,0x148 ; call mtx_lock`), not rendezvous. The real one is
     * the unique 0x1D-byte arg-shuffle leaf. */
    .FUN_SMP_RENDEZVOUS        = 0xB03BA0,
    /* The CFI THUNK 0x261E08, not the real function 0xB03960. smp_rendezvous_action compares
     * the setup/teardown pointers against this address literally and the CFI range check
     * admits only thunks -- same reasoning as off_1200. */
    .FUN_SMP_NO_RENDEVOUS_BARRIER = 0x261E08,

    /* CONFIRMED. Both are H-relative; H = 0x62800000 on this console, so the absolute
     * physicals below hold for it. If H is ever different, these must be recomputed as
     * H + 0x6F00 and H + 0x47375 respectively -- the loader's shellcode_kernel consumes
     * them as raw physicals in patch_hv().
     *   HV_CODE_CAVE_PA     = H + 0x6F00  , inner-container VA 0x6F00 (NOT in the hypercore).
     *                         2990 file-backed 0xCC bytes from 0x6452, 0x100 free from
     *                         0x6F00, inside the loader's identity map [0x62804000,0x62807000)
     *                         whose NX bit is clear (attr 0x280; (attr>>8)<<63 overflows to 0).
     *   HV_HANDLE_VMEXIT_PA = H + 0x47375 , inner-hypercore VA 0x14375. Found by the CPL gate
     *                         `cmp byte [VMCB+4CBh],0` (unique at 0x14379) plus the single
     *                         EXITCODE switch (table 0x181FC, lowcase 0x14, cmp rcx,7Ah) --
     *                         exactly one case targets it, and IDA calls it
     *                         "jumptable 0x13D00 case 129". It is a mid-function block head,
     *                         not a round ...800, same as 12.00. 13.60 is +0x200 above
     *                         12.00's 0x62847175. */
    .HV_CODE_CAVE_PA           = 0x62806F00,   /* H + 0x6F00 */
    .HV_HANDLE_VMEXIT_PA       = 0x62847375,   /* H + 0x47375 */

    /* ---- guest patches ---- */
    .KERNEL_UART_OVERRIDE      = 0x21F9598,
    /* cfi_check_fail -- string xref at 0xFFFFFFFF81521BFC -> 0x8065F925. Byte-for-byte the
     * same 0x83-byte function 7.61 patches at 0x4757B0, only the prologue reordered; 7315
     * xrefs (7.61: 7093, 12.00: 7351). 0xC3 over byte 0 is right because the ordinary path
     * here is a hard fail. */
    .KERNEL_CFI_CHECK          = 0x44F8C0,

    /* ---- boot plumbing ---- */
    .G_VBIOS                   = 0x3DDB9F0,
    /* Real function, not the thunk. The thunk 0x39B3B0 (push rbp; mov rbp,rsp; pop rbp;
     * jmp 0xC0EAA0) was tried and is BEHAVIOURALLY NEUTRAL -- it forwards rdi/rsi untouched, and
     * "a plain thunk and its target are the same function" (the verifier says so for printf).
     * The mp3 wrappers are NOT counter-examples: 0x818960 (cmd 21) and 0x818980 (cmd 22) are
     * ordinary command functions that SET an argument (mov edi,cmd), whereas a CFI thunk is a bare
     * jmp with no arg setup. Thunks are only load-bearing when an address is compared LITERALLY,
     * which is FUN_SMP_NO_RENDEVOUS_BARRIER's case, not this one. Reverted so this run's signal is
     * unambiguous: the content is the returned rc values, the link delay, and the cmdline. */
    .FUN_TRANSMITTER_CONTROL   = 0xC0EAA0,
    /* ***** CONFIRMED ON HARDWARE 2026-10-15: THIS IS THE 13.60 NO-VIDEO BUG *****
     * Was 0xB1B020, the BIG function that references the string "HDCP mp3 lock". That is
     * NOT mp3_initialize -- it is a different function that merely mentions mp3, and every
     * table from 10.00 up had been pointing at it, while 4.51 and 7.61 (the only firmwares
     * that ever produced a picture) pointed at the small wrapper.
     *
     * 0xA14130 is 13.60's unique small wrapper:
     *     55 48 89 e5 53 50 89 fe bf <imm32> e8 ...
     *     push rbp/rbx ; mov esi,edi ; mov edi,<id> ; call
     * matching the loader's `int mp3_initialize(int vmid)`. It passes the SAME two ids
     * 0x5210550 / 0x5210544 on all nine versions 4.51..13.60, sits ~0x1200-0x1400 after
     * FUN_MP3_INVOKE on every one of them, and is a UNIQUE shape per kernel.
     *
     * MEASURED with this value on 13.60: 60f9=1b, 6070=98086504, link 4x0x1e -- the exact
     * signature of video-working 7.61. Before it: 60f9=0b, bit 4 never set. */
    .FUN_MP3_INITIALIZE        = 0xA14130,
    .FUN_MP3_INVOKE            = 0xA12D30,
    /* Confirmed by two independent methods: the getter constant, and the FW_HAS_LAST_BLOCK
     * terminator at +0x7A238 (+16 = 0x7A248). */
    .PS5_WIFI_FW_OFFSET        = 0x1518160,
    .PS5_WIFI_FW_SIZE          = 500296,   /* 0x7A248 */

    /* the two former hardcodes in hv_defeat_13xx.c, now table-driven */
    .NVS_SIZETAB      = 0x1A1A030,
    .PRELOAD_METADATA = 0x3DF1070,
};

/* ======================================================================
 * TABLES DERIVED 2026-10-15 BY SIGNATURE. NOT BOOTED.
 *
 * Every field comes from a method that reproduces the recorded value on EVERY firmware
 * that already records it: ACPIGBL_FACS 10/10, COMMON_TSS 10/10, FUN_MEMCPY 8/8 (>=7.00),
 * G_VBIOS 12/12, the three video functions 12/12 each, IDT 7/7 (>=7.20),
 * KERNEL_SYM_HV_MP_STARTUP_CALL 5/5, and all 25 gadgets 145/145.
 * Each emitted table was then re-verified independently: every gadget was disassembled at
 * its emitted offset and required to decode to the learned instruction sequence, and every
 * signature field was re-derived. 22/22 tables passed with zero disagreements.
 *
 * GADGETS ARE NOT LINEAR-SWEEP ALIGNED, and that is correct: `pop rax ; ret` is normally a
 * MISALIGNED reinterpretation of the middle of another instruction, which is exactly what
 * makes it a gadget. An earlier version of the finder required boundary alignment and
 * silently dropped every pop-style gadget.
 *
 * DELIBERATELY ABSENT from all of these: HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA,
 * KERNEL_SYM_DATA_CAVE, KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * The HV_* pair lives in the HYPERVISOR image, not x86_kernel.elf. The rest had methods
 * tried that did not reach 100% on the knowns, so they are omitted rather than guessed.
 * offsets_present() / hv_defeat_0607 will REFUSE a table that is missing what they need,
 * which is the correct outcome: fail loudly instead of arming a wrong address.
 * ====================================================================== */

/*
 * FW 13.20 (devkit) -- fully derived 2026-10-15. NOT BOOTED.
 * Every method below reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_tables.py for the per-method scores.
 * IDT is COMMON_TSS - 0x2CE0, which holds for every known >= 7.20 (the delta is
 * 0x2BB0 at 5.00, 0x2C20 at 6.00 and 0x2CC0 at 7.00 -- do not use it below 7.20).
 * HV_CODE_CAVE_PA / HV_HANDLE_VMEXIT_PA are NOT derived here: they come from the
 * hypervisor image, not the kernel, so they are deliberately left out rather than
 * guessed, and hv_defeat_0607 will refuse this table until they are filled in.
 */

/*
 * FW 13.40 (devkit) -- fully derived 2026-10-15. NOT BOOTED.
 * Every method below reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_tables.py for the per-method scores.
 * IDT is COMMON_TSS - 0x2CE0, which holds for every known >= 7.20 (the delta is
 * 0x2BB0 at 5.00, 0x2C20 at 6.00 and 0x2CC0 at 7.00 -- do not use it below 7.20).
 * HV_CODE_CAVE_PA / HV_HANDLE_VMEXIT_PA are NOT derived here: they come from the
 * hypervisor image, not the kernel, so they are deliberately left out rather than
 * guessed, and hv_defeat_0607 will refuse this table until they are filled in.
 */

/*
 * FW 13.42 (devkit) -- fully derived 2026-10-15. NOT BOOTED.
 * Every method below reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_tables.py for the per-method scores.
 * IDT is COMMON_TSS - 0x2CE0, which holds for every known >= 7.20 (the delta is
 * 0x2BB0 at 5.00, 0x2C20 at 6.00 and 0x2CC0 at 7.00 -- do not use it below 7.20).
 * HV_CODE_CAVE_PA / HV_HANDLE_VMEXIT_PA are NOT derived here: they come from the
 * hypervisor image, not the kernel, so they are deliberately left out rather than
 * guessed, and hv_defeat_0607 will refuse this table until they are filled in.
 */

/*
 * FW 14.00 (devkit) -- fully derived 2026-10-15. NOT BOOTED.
 * Every method below reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_tables.py for the per-method scores.
 * IDT is COMMON_TSS - 0x2CE0, which holds for every known >= 7.20 (the delta is
 * 0x2BB0 at 5.00, 0x2C20 at 6.00 and 0x2CC0 at 7.00 -- do not use it below 7.20).
 * HV_CODE_CAVE_PA / HV_HANDLE_VMEXIT_PA are NOT derived here: they come from the
 * hypervisor image, not the kernel, so they are deliberately left out rather than
 * guessed, and hv_defeat_0607 will refuse this table until they are filled in.
 */

/*
 * FW 8.20 -- derived 2026-10-15 by signature. NOT BOOTED. 34 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 8.40 -- derived 2026-10-15 by signature. NOT BOOTED. 33 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 8.60 -- derived 2026-10-15 by signature. NOT BOOTED. 33 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 9.20 -- derived 2026-10-15 by signature. NOT BOOTED. 36 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 9.40 -- derived 2026-10-15 by signature. NOT BOOTED. 36 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 9.60 -- derived 2026-10-15 by signature. NOT BOOTED. 36 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 10.01 -- derived 2026-10-15 by signature. NOT BOOTED. 40 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 10.20 -- derived 2026-10-15 by signature. NOT BOOTED. 40 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 10.40 -- derived 2026-10-15 by signature. NOT BOOTED. 40 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 10.60 -- derived 2026-10-15 by signature. NOT BOOTED. 40 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 11.20 (devkit) -- fully derived 2026-10-15. NOT BOOTED.
 * Every method below reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_tables.py for the per-method scores.
 * IDT is COMMON_TSS - 0x2CE0, which holds for every known >= 7.20 (the delta is
 * 0x2BB0 at 5.00, 0x2C20 at 6.00 and 0x2CC0 at 7.00 -- do not use it below 7.20).
 * HV_CODE_CAVE_PA / HV_HANDLE_VMEXIT_PA are NOT derived here: they come from the
 * hypervisor image, not the kernel, so they are deliberately left out rather than
 * guessed, and hv_defeat_0607 will refuse this table until they are filled in.
 */

/*
 * FW 11.40 -- derived 2026-10-15 by signature. NOT BOOTED. 40 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 11.60 -- derived 2026-10-15 by signature. NOT BOOTED. 40 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 12.02 -- derived 2026-10-15 by signature. NOT BOOTED. 41 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 12.20 -- derived 2026-10-15 by signature. NOT BOOTED. 41 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 12.40 -- derived 2026-10-15 by signature. NOT BOOTED. 41 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 12.60 -- derived 2026-10-15 by signature. NOT BOOTED. 41 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */

/*
 * FW 12.70 -- derived 2026-10-15 by signature. NOT BOOTED. 41 fields.
 * Every method reproduces the recorded value on every firmware that has one;
 * see scratchpad/emit_full.py for the per-method scores.
 * ABSENT ON PURPOSE (no method reached 100%): KERNEL_UART_OVERRIDE, IOMMU_SOFTC,
 * HV_CODE_CAVE_PA, HV_HANDLE_VMEXIT_PA, KERNEL_SYM_DATA_CAVE,
 * KERNEL_SYM_MP_STARTUP_INIT_VECTOR, NVS_SIZETAB, PRELOAD_METADATA.
 * offsets_present() refuses a table missing what the route needs -- by design.
 */
