#include "utils.h"
#include "shellcode_hypervisor_args.h"
#include <cpuid.h>

extern shellcode_hypervisor_args args;

__attribute__((noinline, optimize("O0"))) uint32_t putc_uart(uint8_t tx_byte) {
  volatile uint32_t *uart_tx = 0xc1010104ULL;
  volatile uint32_t *uart_busy = 0xc101010cULL;
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

// Variable for val to hex
uint8_t hex_val[17];

__attribute__((noinline, optimize("O0"))) uint8_t *
u64_to_hex_custom(uint64_t val, uint8_t *dest) {

  const uint8_t hex_chars[] = "0123456789abcdef";
  dest[16] = '\0';

  for (int i = 15; i >= 0; i--) {
    dest[i] = hex_chars[val & 0xf];
    val >>= 4;
  }
  return dest;
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

// Map FreeBSD atomic_add_32 to GCC builtin
void atomic_add_32(volatile uint32_t *p, uint32_t v) {
  __sync_fetch_and_add(p, v);
}

// Map FreeBSD atomic_cmpset_32 to GCC builtin
int atomic_cmpset_32(volatile uint32_t *dst, uint32_t exp, uint32_t src) {
  return __sync_bool_compare_and_swap(dst, exp, src);
}

uint8_t get_cpu(void) {
  uint32_t eax, ebx, ecx, edx;
  __get_cpuid(1, &eax, &ebx, &ecx, &edx);
  uint8_t cpu_id = (ebx >> 24) & 0xFF;
  return cpu_id;
}