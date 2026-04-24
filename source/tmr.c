#include "tmr.h"
#include "utils.h"

uint32_t tmr_read(uint32_t addr) {
  kwrite32(ECAM_B0D18F2 + TMR_INDEX_OFF, addr);
  return kread32(ECAM_B0D18F2 + TMR_DATA_OFF);
}

void tmr_write(uint32_t addr, uint32_t val) {
  kwrite32(ECAM_B0D18F2 + TMR_INDEX_OFF, addr);
  kwrite32(ECAM_B0D18F2 + TMR_DATA_OFF, val);
}