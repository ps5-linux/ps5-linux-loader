#ifndef HV_DEFEAT_H
#define HV_DEFEAT_H

#include "iommu.h"
#include <stdint.h>

int hv_defeat(void);
int stage1_tmr_relax(void);
int stage2_find_vmcbs(void);
uint64_t get_vmcb(int core);
int iommu_selftest(void);
int stage3_patch_vmcbs(void);
int stage4_force_vmcb_reload(void);
int stage5_remove_xotext(void);
int stage6_kernel_pmap_invalidate_all(void);
int stage7_install_kexec(void);
int kexec(uint64_t fptr);

#endif