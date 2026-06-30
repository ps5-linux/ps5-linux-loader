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
} offset_list;

extern offset_list off_0300;
extern offset_list off_0310;
extern offset_list off_0320;
extern offset_list off_0321;
extern offset_list off_0400;
extern offset_list off_0402;
extern offset_list off_0403;
extern offset_list off_0450;
extern offset_list off_0451;
extern offset_list off_0500;
extern offset_list off_0502;
extern offset_list off_0510;
extern offset_list off_0550;
extern offset_list off_0600;
extern offset_list off_0602;
extern offset_list off_0720;
extern offset_list off_0761;

#endif
