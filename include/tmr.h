#ifndef TMR_H
#define TMR_H

#include <stdint.h>

#define ECAM_B0D18F2 dmap + (0xF0000000ULL + 0x18ULL * 0x8000 + 2 * 0x1000)
#define TMR_INDEX_OFF 0x80
#define TMR_DATA_OFF 0x84

#define TMR_BASE(n) ((n) * 0x10 + 0x00)
#define TMR_LIMIT(n) ((n) * 0x10 + 0x04)
#define TMR_CONFIG(n) ((n) * 0x10 + 0x08)
#define TMR_REQUESTORS(n) ((n) * 0x10 + 0x0C)
#define TMR_CFG_PERMISSIVE 0x3F07

uint32_t tmr_read(uint32_t addr);
void tmr_write(uint32_t addr, uint32_t val);

#endif