#ifndef HV_0250_H
#define HV_0250_H

#include "offsets_0250.h"
#include <stdint.h>

#define ECAM_BASE_PA 0xF0000000ULL
#define ECAM_B0D18F2 (ECAM_BASE_PA + 0x18ULL * 0x8000 + 2 * 0x1000)
#define TMR_INDEX_OFF 0x80
#define TMR_DATA_OFF 0x84

#define TMR_BASE(n) ((n) * 0x10 + 0x00)
#define TMR_LIMIT(n) ((n) * 0x10 + 0x04)
#define TMR_CONFIG(n) ((n) * 0x10 + 0x08)
#define TMR_CFG_PERMISSIVE 0x3F07
#define MAX_TMR 22
#define MAX_SAVED_TMRS 8

#define VMCB_NP_ENABLE 0x90
#define VMCB_N_CR3 0xB0

#define MAX_VMCBS 16
struct hv_defeat_ctx {
  uint32_t fw;
  uint64_t kbase;
  uint64_t dmap_base;
  uint32_t uart_route_original;
  int uart_route_changed;

  uint32_t saved_tmrs[MAX_SAVED_TMRS * 2];
  int saved_tmr_count;
  int tmr_disabled;

  uint64_t hv_data_pa;
  uint64_t vmcb_pas[MAX_VMCBS];
  uint64_t vmcb_np_original[MAX_VMCBS];
  uint64_t vmcb_n_cr3;
  int vmcb_count;
  int vmcbs_patched;
};

#endif
