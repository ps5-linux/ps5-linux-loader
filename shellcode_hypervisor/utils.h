#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

uint32_t putc_uart(uint8_t tx_byte);
int printf(const uint8_t *msg);
uint8_t *u64_to_hex_custom(uint64_t val, uint8_t *dest);

extern uint8_t hex_val[17];

inline int print_val64(uint64_t val) {
  return printf(u64_to_hex_custom(val, hex_val));
}

void memcpy(void *dest, void *src, uint64_t len);
char *strcpy(char *dest, const char *src);
void *memset(void *s, int c, uint64_t n);

void disable_intr(void);
void halt(void);
uint64_t rdmsr(uint32_t msr);
void wrmsr(uint32_t msr, uint64_t val);
void atomic_add_32(volatile uint32_t *p, uint32_t v);
int atomic_cmpset_32(volatile uint32_t *dst, uint32_t exp, uint32_t src);
uint8_t get_cpu(void);

#endif