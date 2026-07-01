#include "utils.h"

// 7.xx offsets
#define HV_REENTER_HYPERCORE_07xx 0x0000000062806380ULL
#define HV_STACK_TABLE_07xx 0x000000006282E120ULL
#define HV_PML4_07xx 0x000000006282E1A0ULL
#define HV_ENTRY_07xx 0x000000006282E1B8ULL
#define HV_MAIN_07xx 0x0000000000000E20
#define G_VM_TAB_07xx 0x0000000000027C80

// 6.50 offsets
#define HV_REENTER_HYPERCORE_0650 0x0000000062806780ULL
#define HV_STACK_TABLE_0650 0x000000006282D0C0ULL
#define HV_PML4_0650 0x000000006282D140ULL
#define HV_ENTRY_0650 0x000000006282D158ULL
#define HV_MAIN_0650 0x0000000000000F10
#define G_VM_TAB_0650 0x0000000000023C80

#define MSR_APICBASE 0x01b
#define MSR_GSBASE 0xc0000101

#define DEFAULT_APIC_BASE 0xfee00000

#define APICBASE_ENABLED 0x00000800
#define APICBASE_BSP 0x00000100

#define NESTED_CTRL_NP_ENABLE 0x1

__attribute__((section(".entry_point"), naked)) uint32_t main(void) {
  volatile int fw_version = 0x11AA11AA; // To be updated by loader

  uint64_t hv_pml4 = *(uint64_t *) (fw_version==0x0650 ? HV_PML4_0650 : HV_PML4_07xx);
  uint64_t hv_base = fw_version==0x0650 ? (*(uint64_t *) HV_ENTRY_0650 - HV_MAIN_0650) : (*(uint64_t *) HV_ENTRY_07xx - HV_MAIN_07xx);

  uintptr_t *g_vm_tab =
      (uintptr_t *)vtophys_custom(hv_base + (fw_version==0x0650 ? G_VM_TAB_0650 : G_VM_TAB_07xx), hv_pml4);
  for (int i = 0; i < 16; i++) {
    uintptr_t vc = vtophys_custom(g_vm_tab[i], hv_pml4);
    uintptr_t vmcb = vtophys_custom(*(uintptr_t *)(vc + 0x08), hv_pml4);

    if (i == 0) {
      // Restore guest_apic_base.
      *(uint64_t *)(vc + 0xe8) =
          DEFAULT_APIC_BASE | APICBASE_ENABLED | APICBASE_BSP;
    }

    // Disable nested paging.
    *(uint64_t *)(vmcb + 0x90) &= ~NESTED_CTRL_NP_ENABLE;
  }

  // Restore host apic base.
  wrmsr(MSR_APICBASE, DEFAULT_APIC_BASE | APICBASE_ENABLED | APICBASE_BSP);

  // Restore gs base.
  wrmsr(MSR_GSBASE, ((uint64_t *) (fw_version==0x0650 ? HV_STACK_TABLE_0650 : HV_STACK_TABLE_07xx) )[0] + 0x1000);

  // Reenter hypercore.
  void (*hv_reenter_hypercore)(void) = (void *) (fw_version==0x0650 ? HV_REENTER_HYPERCORE_0650 : HV_REENTER_HYPERCORE_07xx) ;
  hv_reenter_hypercore();
  while (1)
    ;
}
