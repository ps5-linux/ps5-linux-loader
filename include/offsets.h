#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

typedef struct _offset_list {
  /* Loader utils */
  uint64_t IOMMU_SOFTC;
  uint64_t VMSPACE_VM_VMID;
  uint64_t VMSPACE_VM_PMAP;
  uint64_t DATA_BASE_GVMSPACE;
  /* Shellcode Kernel */
  uint64_t HOOK_ACPI_WAKEUP_MACHDEP;
  uint64_t KERNEL_CODE_CAVE;
  uint64_t KERNEL_DATA_CAVE;
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
  uint64_t KERNEL_DEBUG_PATCH;
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

#endif
