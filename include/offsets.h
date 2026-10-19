#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

typedef struct _offset_list {
  /* Loader utils */
  uint64_t IOMMU_SOFTC;
  uint64_t VMSPACE_VM_VMID;
  uint64_t VMSPACE_VM_PMAP;
  uint64_t DATA_BASE_GVMSPACE;
  /* Offsets for 5.00-6.02 hv exploit */
  uint64_t ACPIGBL_FACS;
  uint64_t IDT;
  uint64_t COMMON_TSS;
  uint64_t STOPPED_CPUS;
  uint64_t FUN_STOP_CPUS;
  uint64_t FUN_AS_LAPIC_EOI;
  uint64_t FUN_HV_UNMAP_PT_TMR;
  uint64_t FUN_MEMCPY;
  uint64_t GAD_ADD_RSP_28_POP_RBP_RET;
  uint64_t GAD_IRETQ;
  uint64_t GAD_POP_RAX_RET;
  uint64_t GAD_POP_RDI_RET;
  uint64_t GAD_POP_RSI_RET;
  uint64_t GAD_POP_RDX_RET;
  uint64_t GAD_POP_RCX_RET;
  uint64_t GAD_POP_RSP_RET;
  uint64_t GAD_WRMSR_RET;
  uint64_t GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET;
  /* Shellcode Kernel */
  uint64_t HOOK_ACPI_WAKEUP_MACHDEP;
  uint64_t KERNEL_CODE_CAVE;
  uint64_t FUN_PRINTF;
  uint64_t FUN_HV_IOMMU_SET_BUFFERS;
  uint64_t FUN_HV_IOMM_WAIT_COMPLETION;
  uint64_t FUN_SMP_RENDEZVOUS;
  uint64_t FUN_SMP_NO_RENDEVOUS_BARRIER;
  /* Shellcode HV */
  uint64_t HV_CODE_CAVE_PA;
  uint64_t HV_HANDLE_VMEXIT_PA;
  /* Patches on Kernel */
  uint64_t KERNEL_UART_OVERRIDE;
  uint64_t KERNEL_CFI_CHECK;
  /* Internal functions to prepare boot */
  uint64_t G_VBIOS;
  uint64_t FUN_TRANSMITTER_CONTROL;
  uint64_t FUN_MP3_INITIALIZE;
  uint64_t FUN_MP3_INVOKE;
  /* Wifi FW */
  uint64_t PS5_WIFI_FW_OFFSET;
  uint64_t PS5_WIFI_FW_SIZE;
  /* ---- 13.60 khook port (hv_defeat_13xx) ----
   * All of these are byte-verified against k1360_verify.i64 by
   * HVXring0/ida/verify_reborn_k1360.py, which prints SAFE TO SEND. See
   * HVXring0/findings/VERIFY-reborn-offsets-13.60.md. The hook rewrites the live
   * registers of the intercepted function, so these gadget SEMANTICS are load-bearing,
   * not just their addresses. */
  uint64_t KERNEL_SYM_HV_MP_STARTUP_CALL;   /* the kernel wrapper for HCALL 0x0f */
  uint64_t KERNEL_SYM_MP_STARTUP_INIT_VECTOR; /* the real AP entry the payload returns to */
  uint64_t KERNEL_SYM_DATA_CAVE;            /* khook scratch + oracle home */
  uint64_t GAD_PIVOT_ADD_RSP28_RET;         /* add rsp,0x28 ; ret  -- KHook's IST pivot */
  uint64_t GAD_POP_R8_RET;
  uint64_t GAD_STORE_RCX_R8_RET;            /* mov [rcx],r8  ; ret */
  uint64_t GAD_STORE_RDI8_RCX_RET;          /* mov [rdi+8],rcx ; ret  (TSS IST re-arm) */
  uint64_t GAD_OR_RCX_EAX_RET;              /* or [rcx],eax ; ret     (persistent RF path) */
  uint64_t GAD_SET_DR7_RAX;                 /* mov dr7,rax ; mov eax,r8d ; ret */
  uint64_t GAD_ST_RCX_RDX_RET;              /* mov [rcx],rdx ; ret */
  uint64_t GAD_ST_RCX_RAX_RET;              /* mov [rcx],rax ; xor eax,eax ; ret */
  uint64_t GAD_MOV_RAX_RSI_RET;
  uint64_t GAD_MOV_RAX_RDI_RET;
  uint64_t GAD_REP_MOVSB;
  uint64_t GAD_CLD_RET;
  uint64_t GAD_RET_TRAMP;                   /* a bare ret */
  uint64_t GAD_DBREG_RESUME;
  /* ---- RETARGET SET: used when a kernel lacks 13.60's rcx/r8 store gadgets ----
   * 7.61 and 8.00 contain NONE of mov [rcx],rax / mov [rcx],rdx / mov [rcx],r8 /
   * mov [rdi+8],rcx / pop r8 / mov dr7,rax / or [rcx],eax at a drop-in ret, and 13.60
   * contains neither of these two. The inventories are disjoint, so a table supplies
   * whichever pair its kernel actually has and khook picks the matching emission.
   * A table that sets these MUST leave GAD_STORE_RCX_R8_RET zero: that is the signal. */
  uint64_t GAD_STORE_RDI_RAX_RET;           /* mov [rdi],rax ; ret */
  uint64_t GAD_OR_RSI_ECX_RET;              /* or [rsi],ecx ; ret  (persistent RF path) */
  /* hv_defeat_13xx image checks. Both were 13.60 hardcodes and both are version-specific:
   * NVS_SIZETAB is the 7-qword fingerprint the validity gate compares, PRELOAD_METADATA is
   * the EFI preload pointer derive_H() walks to find the HV carveout base. */
  uint64_t NVS_SIZETAB;
  uint64_t PRELOAD_METADATA;

                /* resumectx tail: DR0 <- RAX, then [rdi+80h..A0h] */
} offset_list;

extern offset_list off_1360;

#endif
