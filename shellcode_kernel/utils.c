#include "utils.h"
#include "shellcode_kernel_args.h"

extern shellcode_kernel_args args;

uint64_t PHYS_TO_DMAP(uint64_t pa) { return args.dmap_base + pa; }

void memcpy(void *dest, void *src, uint64_t len) {
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (uint64_t i = 0; i < len; i++) {
    d[i] = s[i];
  }
}

uint64_t read_cr3(void) {
  uint64_t cr3;
  __asm__ volatile("mov %%cr3, %0"
                   : "=r"(cr3)
                   :
                   :
  );
  return cr3;
}

// for ring0
uint64_t va_to_pa_kernel(uint64_t va) {
  uint64_t cr3 = read_cr3();
  return va_to_pa_custom(va, cr3);
}

// Source: PS5_kldload
uint64_t va_to_pa_custom(uint64_t va, uint64_t cr3_custom) {

  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;
    uint64_t entry_va = PHYS_TO_DMAP(PAGE_PA(table_phys) + idx * 8);

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

__attribute__((noinline, optimize("O0"))) uint32_t putc_uart(uint64_t dmap,
                                                             uint8_t tx_byte) {
  volatile uint32_t *uart_tx = (uint32_t *) (dmap + 0xc1010104ULL);
  volatile uint32_t *uart_busy = (uint32_t *) (dmap + 0xc101010cULL);
  uint64_t timeout = 0xFFFFFFFF;
  do {
    timeout--;
    if (timeout == 0)
      break;
  } while (((*uart_busy) & 0x20) == 0);

  if (timeout == 0)
    return -1;

  *uart_tx = (uint32_t)tx_byte & 0xFF;
  return 0;
}