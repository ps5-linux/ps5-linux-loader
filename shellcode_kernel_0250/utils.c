#include "utils.h"
#include "main.h"

#define UART_ROUTE_CONTROL_PA 0xC0115110ULL
#define UART_TX_PA 0xC1010104ULL
#define UART_STATUS_PA 0xC101010CULL
#define UART_TX_FULL 0x800U
#define UART_TIMEOUT 0x1000000U

uint64_t phys_to_dmap(uint64_t pa) { return args.dmap_base + pa; }

void copy_bytes(void *dest, const void *src, uint64_t len) {
  uint8_t *out = dest;
  const uint8_t *in = src;
  for (uint64_t i = 0; i < len; i++)
    out[i] = in[i];
}

void zero_bytes(void *dest, uint64_t len) {
  uint8_t *out = dest;
  for (uint64_t i = 0; i < len; i++)
    out[i] = 0;
}

int bytes_equal(const void *left, const void *right, uint64_t len) {
  const uint8_t *a = left;
  const uint8_t *b = right;
  for (uint64_t i = 0; i < len; i++) {
    if (a[i] != b[i])
      return 0;
  }
  return 1;
}

void init_global_pointers(volatile shellcode_kernel_args *args_ptr) {
  copy_bytes(&args, (const void *)args_ptr, sizeof(args));
  smp_rendezvous =
      (void (*)(void (*)(void *), void (*)(void *), void (*)(void *),
                void *))args.fun_smp_rendezvous;
  smp_no_rendevous_barrier =
      (void (*)(void *))args.fun_smp_no_rendevous_barrier;
}

void activate_uart_0250(void) {
  volatile uint32_t *route =
      (volatile uint32_t *)phys_to_dmap(UART_ROUTE_CONTROL_PA);
  *route &= ~0x200U;
}

int uart_putc(uint8_t value) {
  volatile uint32_t *tx = (volatile uint32_t *)phys_to_dmap(UART_TX_PA);
  volatile uint32_t *status =
      (volatile uint32_t *)phys_to_dmap(UART_STATUS_PA);

  for (uint32_t timeout = UART_TIMEOUT; timeout; timeout--) {
    if ((*status & UART_TX_FULL) == 0) {
      *tx = value;
      return 0;
    }
    __asm__ volatile("pause");
  }
  return -1;
}

int uart_puts(const char *value) {
  for (uint32_t i = 0; value[i] && i < 128; i++) {
    if (value[i] == '\n' && uart_putc('\r'))
      return -1;
    if (uart_putc((uint8_t)value[i]))
      return -1;
  }
  return 0;
}

void uart_marker(const char *value) { uart_puts(value); }
