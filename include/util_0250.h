#ifndef UTIL_0250_H
#define UTIL_0250_H

#include "hv_0250.h"
#include "utils.h"
#include <sys/cpuset.h>

static inline uint64_t kr8_0250(uint64_t address) {
  uint64_t value = 0;
  return kernel_copyout(address, &value, sizeof(value)) ? 0 : value;
}

static inline uint32_t kr4_0250(uint64_t address) {
  uint32_t value = 0;
  return kernel_copyout(address, &value, sizeof(value)) ? 0 : value;
}

static inline void kw8_0250(uint64_t address, uint64_t value) {
  kernel_copyin(&value, address, sizeof(value));
}

static inline void kw4_0250(uint64_t address, uint32_t value) {
  kernel_copyin(&value, address, sizeof(value));
}

static inline uint32_t dr4_0250(uint64_t dmap_base, uint64_t pa) {
  return kr4_0250(dmap_base + pa);
}

static inline void dw4_0250(uint64_t dmap_base, uint64_t pa, uint32_t value) {
  kw4_0250(dmap_base + pa, value);
}

static inline uint32_t tmr_read_0250(uint64_t dmap_base, uint32_t address) {
  dw4_0250(dmap_base, ECAM_B0D18F2 + TMR_INDEX_OFF, address);
  return dr4_0250(dmap_base, ECAM_B0D18F2 + TMR_DATA_OFF);
}

static inline void tmr_write_0250(uint64_t dmap_base, uint32_t address,
                                  uint32_t value) {
  dw4_0250(dmap_base, ECAM_B0D18F2 + TMR_INDEX_OFF, address);
  dw4_0250(dmap_base, ECAM_B0D18F2 + TMR_DATA_OFF, value);
}

static inline int pin_to_core_0250(int core) {
  uint64_t mask[2] = {1ULL << core, 0};
  return cpuset_setaffinity(3, 1, -1, sizeof(mask), (const cpuset_t *)mask);
}

static inline int unpin_0250(void) {
  uint64_t mask[2] = {0xFFFF, 0};
  return cpuset_setaffinity(3, 1, -1, sizeof(mask), (const cpuset_t *)mask);
}

static inline uint64_t pmap_kextract_0250(uint64_t va) {
  int32_t dmpml4i = 0;
  int32_t dmpdpi = 0;
  int32_t pml4pml4i = 0;

  if (kernel_copyout(ktext + FW_0250_DMPML4I, &dmpml4i, sizeof(dmpml4i)) ||
      kernel_copyout(ktext + FW_0250_DMPDPI, &dmpdpi, sizeof(dmpdpi)) ||
      kernel_copyout(ktext + FW_0250_PML4PML4I, &pml4pml4i,
                     sizeof(pml4pml4i)) ||
      dmpml4i < 0x100 || dmpml4i > 0x1FF || dmpdpi < 0 || dmpdpi > 0x1FF ||
      pml4pml4i < 0x100 || pml4pml4i > 0x1FF)
    return 0;

  uint64_t dmap_start = ((uint64_t)dmpdpi << 30) | ((uint64_t)dmpml4i << 39) |
                        0xFFFF800000000000ULL;
  uint64_t dmap_end = ((uint64_t)(dmpml4i + 1) << 39) | 0xFFFF800000000000ULL;
  if (va >= dmap_start && va < dmap_end)
    return va - dmap_start;

  uint64_t pde_address = (((uint64_t)pml4pml4i << 39) |
                          ((uint64_t)pml4pml4i << 30) | 0xFFFF800000000000ULL) +
                         8 * ((va >> 21) & 0x7FFFFFF);
  uint64_t pde = 0;
  if (kernel_copyout(pde_address, &pde, sizeof(pde)) || !(pde & 1))
    return 0;
  if (pde & 0x80)
    return (pde & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFFULL);

  uint64_t pte_address =
      ((va >> 9) & 0xFE0) + dmap_start + (pde & 0xFFFFFFFFFF000ULL);
  uint64_t pte = 0;
  if (kernel_copyout(pte_address, &pte, sizeof(pte)) || !(pte & 1))
    return 0;
  return (pte & 0xFFFFFFFFFF000ULL) | (va & 0x3FFFULL);
}

#define PDE_PRESENT 0
#define PDE_RW 1
#define PDE_PS 7
#define PDE_XOTEXT 58
#define PDE_PRESENT_MASK 1ULL
#define PDE_RW_MASK 1ULL
#define PDE_PS_MASK 1ULL
#define PDE_XOTEXT_MASK 1ULL
#define PDE_ADDR_MASK 0x000FFFFFFFFFF000ULL
#define PDE_FIELD(entry, name) (((entry) >> PDE_##name) & PDE_##name##_MASK)
#define SET_PDE_BIT(entry, name) ((entry) |= PDE_##name##_MASK << PDE_##name)
#define CLEAR_PDE_BIT(entry, name)                                             \
  ((entry) &= ~(PDE_##name##_MASK << PDE_##name))

static inline uint64_t find_pml4e_0250(uint64_t pmap, uint64_t va,
                                       uint64_t *entry) {
  uint64_t pml4 = 0;
  if (kernel_copyout(pmap + FW_0250_PMAP_PM_PML4, &pml4, sizeof(pml4)) ||
      !INKERNEL(pml4))
    return ~0ULL;
  uint64_t address = pml4 + ((va >> 39) & 0x1FF) * 8;
  *entry = 0;
  return kernel_copyout(address, entry, sizeof(*entry)) ? ~0ULL : address;
}

static inline uint64_t find_pdpe_0250(uint64_t pmap, uint64_t va,
                                      uint64_t *entry) {
  uint64_t pml4e;
  if (find_pml4e_0250(pmap, va, &pml4e) == ~0ULL || !PDE_FIELD(pml4e, PRESENT))
    return ~0ULL;
  uint64_t address = dmap + (pml4e & PDE_ADDR_MASK) + ((va >> 30) & 0x1FF) * 8;
  *entry = 0;
  return kernel_copyout(address, entry, sizeof(*entry)) ? ~0ULL : address;
}

static inline uint64_t find_pde_0250(uint64_t pmap, uint64_t va,
                                     uint64_t *entry) {
  uint64_t pdpe;
  if (find_pdpe_0250(pmap, va, &pdpe) == ~0ULL || !PDE_FIELD(pdpe, PRESENT) ||
      PDE_FIELD(pdpe, PS))
    return ~0ULL;
  uint64_t address = dmap + (pdpe & PDE_ADDR_MASK) + ((va >> 21) & 0x1FF) * 8;
  *entry = 0;
  return kernel_copyout(address, entry, sizeof(*entry)) ? ~0ULL : address;
}

static inline uint64_t find_pte_0250(uint64_t pmap, uint64_t va,
                                     uint64_t *entry) {
  uint64_t pde;
  if (find_pde_0250(pmap, va, &pde) == ~0ULL || PDE_FIELD(pde, PS))
    return ~0ULL;
  uint64_t address = dmap + (pde & PDE_ADDR_MASK) + ((va >> 12) & 0x1FF) * 8;
  *entry = 0;
  return kernel_copyout(address, entry, sizeof(*entry)) ? ~0ULL : address;
}

#endif
