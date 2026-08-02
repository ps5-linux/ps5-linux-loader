#include "utils.h"
#include <cpuid.h>

uint64_t vtophys_custom(uint64_t va, uint64_t cr3_custom) {
  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;
    uint64_t entry_va = PAGE_PA(table_phys) + idx * 8;

    entry = *(uint64_t *)entry_va;

    if (!PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = P_SIZE(level);
      return PAGE_PA(entry) | (va & (page_size - 1));
    }

    if (level == 3)
      return PAGE_PA(entry) | (va & 0xFFF);

    table_phys = PAGE_PA(entry);
  }
  return 0;
}

void wrmsr(uint32_t msr, uint64_t val) {
  uint32_t low = val & 0xFFFFFFFF;
  uint32_t high = val >> 32;
  __asm__ __volatile__("wrmsr" : : "a"(low), "d"(high), "c"(msr));
}
