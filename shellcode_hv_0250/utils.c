#include "utils.h"
#include <cpuid.h>

#define UART_ROUTE_CONTROL 0xC0115110ULL
#define UART_TX 0xC1010104ULL
#define UART_STATUS 0xC101010CULL
#define UART_TX_FULL 0x800U
#define UART_TIMEOUT 0x1000000U

static volatile uint32_t uart_lock;

void activate_uart(void) {
  *(volatile uint32_t *)UART_ROUTE_CONTROL &= ~0x200U;
}

int uart_putc(uint8_t value) {
  volatile uint32_t *tx = (volatile uint32_t *)UART_TX;
  volatile uint32_t *status = (volatile uint32_t *)UART_STATUS;
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

static int uart_hex(uint64_t value, uint32_t digits) {
  static const char hex[] = "0123456789abcdef";
  for (uint32_t i = 0; i < digits; i++) {
    uint32_t shift = (digits - i - 1) * 4;
    if (uart_putc((uint8_t)hex[(value >> shift) & 0xF]))
      return -1;
  }
  return 0;
}

void uart_trace(uint8_t event, uint8_t cpu, uint32_t value) {
  uint32_t timeout = UART_TIMEOUT;
  while (__sync_lock_test_and_set(&uart_lock, 1)) {
    if (--timeout == 0)
      return;
    __asm__ volatile("pause");
  }

  if (!uart_puts("[H25:") && !uart_hex(event, 2) && !uart_puts(" c=") &&
      !uart_hex(cpu, 2) && !uart_puts(" v=") && !uart_hex(value, 8))
    uart_puts("]\n");
  __sync_lock_release(&uart_lock);
}

void uart_emergency(const char *value) { uart_puts(value); }

void uart_exception_trace(uint8_t vector, uint8_t cpu, uint64_t rip,
                          uint64_t error) {
  if (!uart_puts("[H25:E") && !uart_hex(vector, 2) && !uart_puts(" c=") &&
      !uart_hex(cpu, 2) && !uart_puts(" rip=") && !uart_hex(rip, 16) &&
      !uart_puts(" err=") && !uart_hex(error, 16))
    uart_puts("]\n");
}

void copy_bytes(void *dest, const void *src, uint64_t len) {
  uint8_t *out = dest;
  const uint8_t *in = src;
  for (uint64_t i = 0; i < len; i++)
    out[i] = in[i];
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

void zero_bytes(void *dest, uint64_t len) {
  uint8_t *out = dest;
  for (uint64_t i = 0; i < len; i++)
    out[i] = 0;
}

void disable_intr(void) { __asm__ volatile("cli" : : : "memory"); }
void halt(void) { __asm__ volatile("hlt"); }

uint64_t rdmsr(uint32_t msr) {
  uint32_t low, high;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return ((uint64_t)high << 32) | low;
}

void wrmsr(uint32_t msr, uint64_t value) {
  __asm__ volatile("wrmsr"
                   :
                   : "a"((uint32_t)value), "d"((uint32_t)(value >> 32)),
                     "c"(msr));
}

uint32_t atomic_add_32(volatile uint32_t *value, uint32_t add) {
  return __sync_add_and_fetch(value, add);
}

uint32_t atomic_or_32(volatile uint32_t *value, uint32_t bits) {
  return __sync_or_and_fetch(value, bits);
}

uint32_t atomic_load_32(volatile uint32_t *value) {
  return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

uint8_t get_cpu(void) {
  uint32_t eax, ebx, ecx, edx;
  __get_cpuid(1, &eax, &ebx, &ecx, &edx);
  return (uint8_t)(ebx >> 24);
}
