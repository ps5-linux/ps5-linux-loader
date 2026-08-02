#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

// Defines for Page management
enum page_bits {
  P = 0,
  RW,
  US,
  PWT,
  PCD,
  A,
  D,
  PS,
  G,
  XO = 58,
  PK = 59,
  NX = 63
};

#define PG_B_P (1ULL << P)
#define PG_B_RW (1ULL << RW)
#define PAGE_P(x) (x & (1ULL << P))
#define PAGE_RW(x) (x & (1ULL << RW))
#define PAGE_PS(x) (x & (1ULL << PS))
#define PAGE_XO(x) (x & (1ULL << XO))
#define PAGE_CLEAR_XO(x) (x &= ~(1ULL << XO))
#define PAGE_CLEAR_G(x) (x &= ~(1ULL << G))
#define PAGE_SET_RW(x) (x |= (1ULL << RW))
#define PAGE_PA(x) (x & 0x000FFFFFFFFFF000ULL)
#define P_SIZE(l) ((l == 1) ? (1ULL << 30) : (1ULL << 21))

uint64_t vtophys_custom(uint64_t va, uint64_t cr3_custom);
void wrmsr(uint32_t msr, uint64_t val);

#endif
