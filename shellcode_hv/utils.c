#include "utils.h"
#include <cpuid.h>

/* Enable the Titania UART from HV / S3-resume context.
 *
 * Polarity and addressing here are the OPPOSITE of the GameOS path:
 *
 *   GameOS  (runtime payload) : *(u32*)(dmap_base + 0xC0115110) = (1<<9);   // SET
 *   HV / resume (this code)   : *(u32*)(0xC0115110)            &= ~(1<<9);  // NEGATE
 *
 * This file already addresses the UART data registers physically (0xC1010104 /
 * 0xC101010C) with no dmap, because the HV shellcode runs after CR3 has been switched
 * to a 1:1 mapping -- so the gate is addressed physically too.
 *
 * The register is WRITE-ONLY: it reads back 0 regardless of what was written. Do not
 * read it back to check, and never conclude the write was discarded from that.
 *
 * Must be re-applied on every resume -- needed for sleep/wake under Linux.
 */
__attribute__((noinline, optimize("O0"))) void activate_uart_hv(void) {
  volatile uint32_t *gate = (volatile uint32_t *)0xC0115110ULL;
  *gate &= ~(1u << 9);
}

__attribute__((noinline, optimize("O0"))) uint32_t putc_uart(uint8_t tx_byte) {
  volatile uint32_t *uart_tx = (volatile uint32_t *)0xc1010104ULL;
  volatile uint32_t *uart_busy = (volatile uint32_t *)0xc101010cULL;
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

__attribute__((noinline, optimize("O0"))) int printf(const uint8_t *msg) {
  uint32_t max = 255;
  int ret = 0;

  for (int i = 0; i < 255; i++) {
    if (msg[i] == '\0') {
      break;
    }
    if (msg[i] == '\n') {
      putc_uart('\r');
    }
    ret = putc_uart(msg[i]);
  }

  return ret;
}

__attribute__((noinline, optimize("O0"))) void memcpy(void *dest, void *src,
                                                      uint64_t len) {
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (uint64_t i = 0; i < len; i++) {
    d[i] = s[i];
  }
}

__attribute__((noinline, optimize("O0"))) char *strcpy(char *dest,
                                                       const char *src) {
  char *d = dest;
  while ((*d++ = *src++)) {
  }
  return dest;
}

__attribute__((noinline, optimize("O0"))) void *memset(void *s, int c,
                                                       uint64_t n) {
  unsigned char *p = (unsigned char *)s;
  while (n--) {
    *p++ = (unsigned char)c;
  }
  return s;
}

void disable_intr(void) { __asm__ __volatile__("cli" : : : "memory"); }

void halt(void) { __asm__ __volatile__("hlt"); }

uint64_t rdmsr(uint32_t msr) {
  uint32_t low, high;
  __asm__ __volatile__("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return ((uint64_t)high << 32) | low;
}

void wrmsr(uint32_t msr, uint64_t val) {
  uint32_t low = val & 0xFFFFFFFF;
  uint32_t high = val >> 32;
  __asm__ __volatile__("wrmsr" : : "a"(low), "d"(high), "c"(msr));
}

void atomic_add_32(volatile uint32_t *p, uint32_t v) {
  __sync_fetch_and_add(p, v);
}

int atomic_cmpset_32(volatile uint32_t *dst, uint32_t exp, uint32_t src) {
  return __sync_bool_compare_and_swap(dst, exp, src);
}

uint8_t get_cpu(void) {
  uint32_t eax, ebx, ecx, edx;
  __get_cpuid(1, &eax, &ebx, &ecx, &edx);
  uint8_t cpu_id = (ebx >> 24) & 0xFF;
  return cpu_id;
}
