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
  __asm__ volatile("mov %%cr3, %0" : "=r"(cr3) : :);
  return cr3;
}

uint64_t vtophys(uint64_t dmap, uint64_t va) {
  uint64_t cr3 = read_cr3();
  return vtophys_custom(dmap, va, cr3);
}

uint64_t vtophys_custom(uint64_t dmap, uint64_t va, uint64_t cr3_custom) {
  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;

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

uint32_t putc_uart(uint64_t dmap, uint8_t tx_byte) {
  volatile uint32_t *uart_tx = (uint32_t *)(dmap + 0xc1010104ULL);
  volatile uint32_t *uart_busy = (uint32_t *)(dmap + 0xc101010cULL);
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

int puts_uart(uint64_t dmap, const uint8_t *msg) {
  uint32_t max = 255;
  int ret = 0;

  for (int i = 0; i < 255; i++) {
    if (msg[i] == '\0') {
      break;
    }
    if (msg[i] == '\n') {
      putc_uart(dmap, '\r');
    }
    ret = putc_uart(dmap, msg[i]);
  }

  return ret;
}

void activate_uart(volatile shellcode_kernel_args *args_ptr) {
  uint32_t *uart_va = (uint32_t *)(args_ptr->dmap_base + 0xC0115110ULL);
  *uart_va &= ~0x200;
  uint32_t *override_char_va = (uint32_t *)args_ptr->kernel_uart_override;
  *override_char_va = 0x0;
}

void halt(void) { __asm__ __volatile__("hlt"); }

void init_global_pointers(volatile shellcode_kernel_args *args_ptr) {
  memcpy(&args, (void *)args_ptr, sizeof(args));

  printf = (void (*)(const char *, ...))args.fun_printf;
  smp_rendezvous = (void (*)(void (*)(void), void (*)(void), void (*)(void),
                             void *))args.fun_smp_rendezvous;
  smp_no_rendevous_barrier = (void (*)(void))args.fun_smp_no_rendevous_barrier;

  transmitter_control = (int (*)(int, void *))args.fun_transmitter_control;
  mp3_initialize = (int (*)(int))args.fun_mp3_initialize;
  mp3_invoke = (int (*)(int, void *, void *))args.fun_mp3_invoke;
  g_vbios = args.g_vbios;
}

void vmmcall_dummy(void) {
  __asm__ volatile("mov $0x1, %rax \n"
                   "vmmcall \n"
                   "ret \n");
}